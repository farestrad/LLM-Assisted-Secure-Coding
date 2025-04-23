import * as vscode from 'vscode';
import Parser from 'tree-sitter';
import C from 'tree-sitter-c';
import { SecurityCheck } from "../c/SecurityCheck";

let parser: Parser;

function initParser() {
    if (!parser) {
        parser = new Parser();
        parser.setLanguage(C as unknown as Parser.Language);
    }
}

export class IntegerFlowCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Get configuration values
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const MAX_INT_CONFIG = config.get<number>('maxIntValue', 2147483647); // Default to INT_MAX (2^31 - 1)
        const MIN_INT_CONFIG = config.get<number>('minIntValue', -2147483648); // Default to INT_MIN (-2^31)
        
        const MAX_INT = MAX_INT_CONFIG; 
        const MIN_INT = MIN_INT_CONFIG;
        
        // Track variables that have been validated
        const validatedVariables = new Set<string>();
        const symbolTable = new Map<string, { value: number | null, line: number }>();
        const overflowRisks = new Map<string, { operations: string[], line: number }>();
        
        initParser();
        const tree = parser.parse(methodBody);

        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }

        function resolveIdentifier(name: string): number | null {
            return symbolTable.has(name) ? symbolTable.get(name)?.value || null : null;
        }

        function trackVariable(name: string, value: number | null, node: Parser.SyntaxNode) {
            symbolTable.set(name, { value, line: getLineNumber(node) });
        }

        function addOverflowRisk(variable: string, operation: string, node: Parser.SyntaxNode) {
            const line = getLineNumber(node);
            if (overflowRisks.has(variable)) {
                overflowRisks.get(variable)?.operations.push(operation);
            } else {
                overflowRisks.set(variable, { operations: [operation], line });
            }
        }

        function evaluate(node: Parser.SyntaxNode): { value: number | null, overflowRisk: boolean } {
            if (!node) return { value: null, overflowRisk: false };

            switch (node.type) {
                case 'number_literal':
                    return { value: parseInt(node.text), overflowRisk: false };
                    
                case 'identifier':
                    return { 
                        value: resolveIdentifier(node.text), 
                        overflowRisk: overflowRisks.has(node.text)
                    };
                    
                case 'binary_expression': {
                    const left = evaluate(node.child(0)!);
                    const operator = node.child(1)?.text;
                    const right = evaluate(node.child(2)!);
                    
                    if (left.value === null || right.value === null || !operator) {
                        return { 
                            value: null, 
                            overflowRisk: left.overflowRisk || right.overflowRisk 
                        };
                    }

                    try {
                        let result: number;
                        let overflowRisk = left.overflowRisk || right.overflowRisk;
                        
                        switch (operator) {
                            case '+': 
                                result = left.value + right.value;
                                if (result > MAX_INT || result < MIN_INT) overflowRisk = true;
                                break;
                            case '-': 
                                result = left.value - right.value;
                                if (result > MAX_INT || result < MIN_INT) overflowRisk = true;
                                break;
                            case '*': 
                                result = left.value * right.value;
                                if (result > MAX_INT || result < MIN_INT) overflowRisk = true;
                                break;
                            case '/': 
                                if (right.value === 0) return { value: null, overflowRisk: false };
                                result = Math.floor(left.value / right.value); // Integer division
                                break;
                            case '%':
                                if (right.value === 0) return { value: null, overflowRisk: false };
                                result = left.value % right.value;
                                break;
                            case '<<':
                                result = left.value << right.value;
                                if (result > MAX_INT) overflowRisk = true;
                                break;
                            case '>>':
                                result = left.value >> right.value;
                                break;
                            default:
                                return { value: null, overflowRisk: overflowRisk };
                        }
                        
                        return { value: result, overflowRisk };
                    } catch {
                        return { value: null, overflowRisk: true };
                    }
                }
                
                case 'unary_expression': {
                    const operator = node.child(0)?.text;
                    const operand = evaluate(node.child(1)!);
                    
                    if (operand.value === null || !operator) {
                        return { value: null, overflowRisk: operand.overflowRisk };
                    }
                    
                    try {
                        let result: number;
                        let overflowRisk = operand.overflowRisk;
                        
                        switch (operator) {
                            case '-': 
                                result = -operand.value;
                                if (result < MIN_INT) overflowRisk = true;
                                break;
                            case '+': 
                                result = operand.value;
                                break;
                            case '~': 
                                result = ~operand.value;
                                break;
                            default:
                                return { value: null, overflowRisk };
                        }
                        
                        return { value: result, overflowRisk };
                    } catch {
                        return { value: null, overflowRisk: true };
                    }
                }
                
                case 'cast_expression': {
                    const castType = node.child(0)?.text || '';
                    const value = evaluate(node.namedChild(0)!);
                    
                    // Check if casting to a smaller type
                    if (value.value !== null) {
                        let overflowRisk = value.overflowRisk;
                        if (castType.includes('char') && (value.value > 127 || value.value < -128)) {
                            overflowRisk = true;
                        } else if (castType.includes('short') && (value.value > 32767 || value.value < -32768)) {
                            overflowRisk = true;
                        } else if (castType.includes('unsigned') && value.value < 0) {
                            overflowRisk = true;
                        }
                        
                        return { value: value.value, overflowRisk };
                    }
                    
                    return { value: null, overflowRisk: value.overflowRisk };
                }
                
                default:
                    return { value: null, overflowRisk: false };
            }
        }

        function traverse(node: Parser.SyntaxNode) {
            // Process conditions as validation checks
            if (node.type === 'if_statement' || node.type === 'while_statement') {
                const condition = node.childForFieldName('condition');
                if (condition) {
                    const variables = extractVariables(condition);
                    variables.forEach(v => validatedVariables.add(v));
                }
            }
            
            // Handle variable declarations with initializers (e.g., int x = a + b;)
            if (node.type === 'declaration') {
                for (const child of node.namedChildren) {
                    if (child.type === 'init_declarator') {
                        const idNode = child.childForFieldName('declarator');
                        const valueNode = child.childForFieldName('value');
                        
                        if (idNode?.type === 'identifier' && valueNode) {
                            const varName = idNode.text;
                            const evalResult = evaluate(valueNode);
                            
                            trackVariable(varName, evalResult.value, child);
                            
                            if (evalResult.overflowRisk && !validatedVariables.has(varName)) {
                                const line = getLineNumber(child);
                                issues.push(
                                    `Warning: Potential integer overflow/underflow detected in method "${methodName}" during declaration of "${varName}" at line ${line}.`
                                );
                            }
                            
                            // Check explicit numeric overflow
                            if (evalResult.value !== null && 
                                (evalResult.value > MAX_INT || evalResult.value < MIN_INT)) {
                                const line = getLineNumber(child);
                                issues.push(
                                    `Warning: Integer overflow/underflow detected in method "${methodName}" during declaration of "${varName}" at line ${line}.`
                                );
                            }
                        }
                    }
                }
            }

            // Handle assignment expressions (e.g., x = a + b;)
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const right = node.child(2);
                const operator = node.child(1)?.text;
                
                if (left?.type === 'identifier' && right) {
                    const varName = left.text;
                    const evalResult = evaluate(right);
                    
                    // Track the variable and its value
                    trackVariable(varName, evalResult.value, node);
                    
                    // Check for compound assignments (+=, -=, *=, etc.)
                    if (operator && operator !== '=') {
                        // Extract the actual operation (+ from +=, etc.)
                        const actualOp = operator.charAt(0);
                        const operation = `${varName} ${actualOp} ...`;
                        addOverflowRisk(varName, operation, node);
                        
                        if (!validatedVariables.has(varName)) {
                            const line = getLineNumber(node);
                            issues.push(
                                `Warning: Potential integer overflow/underflow risk in compound assignment "${operator}" to "${varName}" at line ${line} in method "${methodName}".`
                            );
                        }
                    }
                    
                    // Check for overflow risks in the assignment
                    if (evalResult.overflowRisk && !validatedVariables.has(varName)) {
                        const line = getLineNumber(node);
                        issues.push(
                            `Warning: Potential integer overflow/underflow detected in method "${methodName}" during assignment to "${varName}" at line ${line}.`
                        );
                    }
                    
                    // Check explicit numeric overflow
                    if (evalResult.value !== null && 
                        (evalResult.value > MAX_INT || evalResult.value < MIN_INT)) {
                        const line = getLineNumber(node);
                        issues.push(
                            `Warning: Integer overflow/underflow detected in method "${methodName}" during assignment to "${varName}" at line ${line}.`
                        );
                    }
                }
            }
            
            // Handle arithmetic in function arguments
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text;
                const args = node.child(1);
                
                if (args) {
                    args.namedChildren.forEach((arg, index) => {
                        const evalResult = evaluate(arg);
                        if (evalResult.overflowRisk) {
                            const line = getLineNumber(node);
                            issues.push(
                                `Warning: Potential integer overflow/underflow in argument ${index+1} to function "${fnName}" at line ${line} in method "${methodName}".`
                            );
                        }
                        
                        // Check explicit numeric overflow
                        if (evalResult.value !== null && 
                            (evalResult.value > MAX_INT || evalResult.value < MIN_INT)) {
                            const line = getLineNumber(node);
                            issues.push(
                                `Warning: Integer overflow/underflow detected in argument ${index+1} to function "${fnName}" at line ${line} in method "${methodName}".`
                            );
                        }
                    });
                }
            }
            
            // Check array index calculations for overflow
            if (node.type === 'subscript_expression') {
                const array = node.child(0)?.text;
                const index = node.child(1);
                
                if (array && index) {
                    const evalResult = evaluate(index);
                    if (evalResult.overflowRisk) {
                        const line = getLineNumber(node);
                        issues.push(
                            `Warning: Potential integer overflow/underflow in array index calculation for "${array}" at line ${line} in method "${methodName}".`
                        );
                    }
                    
                    // Check explicit index bounds
                    if (evalResult.value !== null && evalResult.value < 0) {
                        const line = getLineNumber(node);
                        issues.push(
                            `Warning: Negative array index (${evalResult.value}) used with "${array}" at line ${line} in method "${methodName}".`
                        );
                    }
                }
            }
            
            // Detect unsafe typecasts
            if (node.type === 'cast_expression') {
                const type = node.child(0)?.text;
                const expr = node.namedChild(0);
                
                if (type && expr) {
                    // Check for potentially dangerous casts
                    if (type.includes('unsigned') && expr.type === 'identifier') {
                        const varName = expr.text;
                        const varInfo = symbolTable.get(varName);
                        const value = varInfo?.value;
                        
                        if (value !== null && value !== undefined && value < 0) {
                            const line = getLineNumber(node);
                            issues.push(
                                `Warning: Casting negative value (${value}) to unsigned type at line ${line} in method "${methodName}".`
                            );
                        }
                    }
                    
                    // Check for narrowing conversions (e.g., long -> int, int -> short)
                    if ((type.includes('short') || type.includes('char')) && 
                        expr.type === 'identifier') {
                        const varName = expr.text;
                        const varInfo = symbolTable.get(varName);
                        const value = varInfo?.value;
                        
                        if (value !== null && value !== undefined) {
                            let threshold = type.includes('short') ? 32767 : 127;
                            if (value > threshold) {
                                const line = getLineNumber(node);
                                issues.push(
                                    `Warning: Narrowing conversion may lose data at line ${line} in method "${methodName}".`
                                );
                            }
                        }
                    }
                }
            }

            node.namedChildren.forEach(traverse);
        }

        function extractVariables(node: Parser.SyntaxNode): string[] {
            const variables: string[] = [];
            
            if (node.type === 'identifier') {
                variables.push(node.text);
            }
            
            node.namedChildren.forEach(child => {
                variables.push(...extractVariables(child));
            });
            
            return variables;
        }

        // Find validation patterns in code using regex
        findValidationPatterns(methodBody, validatedVariables);
        
        // Process the AST
        traverse(tree.rootNode);
        
        return issues;
    }
}

// Helper function to find common validation patterns using regex
function findValidationPatterns(methodBody: string, validatedVariables: Set<string>): void {
    // Pattern 1: if(var < LIMIT) or similar bounds checks
    const boundsCheckRegex = /if\s*\(\s*(\w+)\s*(?:<|<=|>|>=|==|!=)\s*[^;]+\)/g;
    let match;
    while ((match = boundsCheckRegex.exec(methodBody)) !== null) {
        if (match[1]) validatedVariables.add(match[1]);
    }
    
    // Pattern 2: assert(var < LIMIT) or similar assertions
    const assertRegex = /assert\s*\(\s*(\w+)\s*(?:<|<=|>|>=|==|!=)\s*[^;]+\)/g;
    while ((match = assertRegex.exec(methodBody)) !== null) {
        if (match[1]) validatedVariables.add(match[1]);
    }
    
    // Pattern 3: MACRO_CHECK(var) or similar validation macros
    const macroRegex = /(?:CHECK|VALIDATE|VERIFY|ENSURE)_(?:INT|INTEGER|NUMBER|RANGE|BOUNDS)\s*\(\s*(\w+)[^)]*\)/gi;
    while ((match = macroRegex.exec(methodBody)) !== null) {
        if (match[1]) validatedVariables.add(match[1]);
    }
    
    // Pattern 4: Standard library validation like isValid(), checkRange(), etc.
    const libValidationRegex = /(?:isValid|checkRange|validateInt|isInRange|checkBounds)\s*\(\s*(\w+)[^)]*\)/g;
    while ((match = libValidationRegex.exec(methodBody)) !== null) {
        if (match[1]) validatedVariables.add(match[1]);
    }
}