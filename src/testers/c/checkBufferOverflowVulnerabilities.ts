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

export class BufferOverflowCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const buffers = new Map<string, number>();
        const validationChecks = new Set<string>();
        const validationFunctions = new Set<string>();
        const calledFunctions = new Set<string>();
        const aliases = new Map<string, string>();
        const mallocAssigned = new Set<string>();
        const mallocChecked = new Set<string>();
        const visited = new Set<Parser.SyntaxNode>();
        
        // NEW: Track loop variables and their bounds
        const loopVariables = new Map<string, {
            min: number | null, 
            max: number | null, 
            loopNode: Parser.SyntaxNode
        }>();
        
        // NEW: Track array access operations to verify them against loop bounds
        const arrayAccesses = new Map<string, {
            arrayName: string, 
            indexVar: string, 
            node: Parser.SyntaxNode
        }>();
        
        const unsafeFunctions = new Map<string, string>([
            ['strcpy', 'strncpy'],
            ['strcat', 'strncat'],
            ['gets', 'fgets'],
            ['sprintf', 'snprintf'],
            ['vsprintf', 'vsnprintf'],
            ['gets_s', 'fgets'],
            ['scanf', 'fgets with parsing or use "%Ns"'],
            ['strtok', 'strtok_r'],
            ['asctime', 'asctime_r'],
            ['ctime', 'ctime_r'],
            ['tmpnam', 'mkstemp'],
            ['tmpfile', 'tmpfile_s'],
            ['realpath', 'ensure buffer size is validated'],
        ]);

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const stackThreshold = config.get<number>('stackBufferThreshold', 512);

        initParser();
        const tree = parser.parse(methodBody);

        function extractSizeLiteral(node: Parser.SyntaxNode): number | null {
            if (!node) return null;
        
            if (node.type === 'number_literal') {
                return parseInt(node.text);
            }
        
            // Handle constant identifier (e.g., BUF_SIZE)
            if (buffers.has(node.text)) return buffers.get(node.text)!;
        
            return null;
        }
        
        function evaluateSimpleExpression(expr: string): number | null {
            try {
                // Replace known variables with their values
                const evalExpr = expr.replace(/\b(\w+)\b/g, (match) => {
                    if (buffers.has(match)) {
                        return buffers.get(match)?.toString() || "0";
                    }
                    return '0'; // Unknown variable
                });
                
                // Use safer evaluation
                const result = Function('"use strict"; return (' + evalExpr + ')')();
                return typeof result === 'number' ? result : null;
            } catch (e) {
                // Evaluation failed, return null
            }
            
            return null;
        }

        function isValidatedByFunction(buffer: string): boolean {
            return Array.from(validationFunctions).some(fn =>
                new RegExp(`\\b${fn}\\s*\\(\\s*${buffer}\\s*\\)`).test(methodBody)
            );
        }
        
        // NEW: Check if an index is validated by a loop condition
        function isIndexValidatedByLoop(indexVar: string, arrayName: string, accessNode: Parser.SyntaxNode): boolean {
            // Skip checking if indexVar isn't tracked as a loop variable
            if (!loopVariables.has(indexVar)) return false;
            
            const loopInfo = loopVariables.get(indexVar)!;
            const loopNode = loopInfo.loopNode;
            
            // If max bound is not set, we can't validate
            if (loopInfo.max === null) return false;
            
            // Get the array size if known
            const arraySize = buffers.get(arrayName) || mallocAssigned.has(arrayName) ? 0 : null;
            
            // Is the array access inside the loop?
            let isInsideLoop = false;
            let currentNode: Parser.SyntaxNode | null = accessNode;
            
            while (currentNode && currentNode !== loopNode) {
                currentNode = currentNode.parent;
                if (!currentNode) {
                    break;
                }
            }
            
            isInsideLoop = currentNode === loopNode;
            
            // If the access is inside the loop and the max bound is less than array size (or unknown),
            // we consider it validated
            if (isInsideLoop) {
                if (arraySize === null || loopInfo.max < arraySize) {
                    return true;
                }
            }
            
            return false;
        }

        function traverse(node: Parser.SyntaxNode) {
            if (visited.has(node)) return;
            visited.add(node);
            
            // First process all declarations to get buffer sizes
            if (node.type === 'declaration') {
                const declarator = node.childForFieldName('declarator');
                if (declarator?.type === 'array_declarator') {
                    const name = declarator.childForFieldName('declarator')?.text;
                    const sizeNode = declarator.childForFieldName('size');
                    let size: number | null = null;
                    if (sizeNode) {
                        size = extractSizeLiteral(sizeNode);
                    }

                    if (name && size !== null) {
                        buffers.set(name, size);
                        if (size > stackThreshold) {
                            issues.push(`Warning: Large stack buffer "${name}" (${size} bytes) in "${methodName}" at line ${node.startPosition.row + 1}`);
                        }
                    }
                }
            }
            
            // NEW: Track loop variables and their bounds
            if (node.type === 'for_statement') {
                // 1. Extract initialization (e.g., int i = 0)
                const initNode = node.childForFieldName('initializer');
                
                // 2. Extract condition (e.g., i < 100)
                const conditionNode = node.childForFieldName('condition');
                
                // 3. Extract the loop variable and its bounds
                let loopVar: string | null = null;
                let minBound: number | null = null;
                let maxBound: number | null = null;
                
                // First try to get the variable from initialization
                if (initNode?.type === 'declaration') {
                    const declarators = initNode.descendantsOfType('init_declarator');
                    if (declarators.length > 0) {
                        const declarator = declarators[0];
                        const nameNode = declarator.childForFieldName('declarator');
                        const valueNode = declarator.childForFieldName('value');
                        
                        if (nameNode && valueNode?.type === 'number_literal') {
                            loopVar = nameNode.text;
                            minBound = parseInt(valueNode.text);
                        }
                    }
                } else if (initNode?.type === 'assignment_expression') {
                    const leftNode = initNode.child(0);
                    const rightNode = initNode.child(2);
                    
                    if (leftNode?.type === 'identifier' && rightNode?.type === 'number_literal') {
                        loopVar = leftNode.text;
                        minBound = parseInt(rightNode.text);
                    }
                }
                
                // Then try to get the max bound from condition
                if (conditionNode?.type === 'binary_expression') {
                    const leftNode = conditionNode.child(0);
                    const opNode = conditionNode.child(1);
                    const rightNode = conditionNode.child(2);
                    
                    if (leftNode?.type === 'identifier' && 
                        ['<', '<='].includes(opNode?.text || '') && 
                        rightNode?.type === 'number_literal') {
                        
                        // Only set loopVar if we didn't get it from initialization
                        loopVar = loopVar || leftNode.text;
                        maxBound = parseInt(rightNode.text);
                        
                        // Adjust for <= operator
                        if (opNode?.text === '<=') {
                            maxBound += 1;
                        }
                    }
                }
                
                // Store loop variable and bounds
                if (loopVar) {
                    loopVariables.set(loopVar, {
                        min: minBound,
                        max: maxBound,
                        loopNode: node
                    });
                    
                    // Mark this variable as validated for simpler checks
                    validationChecks.add(loopVar);
                }
            }

            if (node.type === 'if_statement') {
                const cond = node.childForFieldName('condition');
                const ids = cond?.descendantsOfType('identifier') || [];
                for (const id of ids) {
                    mallocChecked.add(id.text);
                    validationChecks.add(id.text);
                }
            }
            
            if (node.type === 'declaration') {
                const declNodes = node.descendantsOfType('init_declarator');
                for (const declNode of declNodes) {
                    const nameNode = declNode.childForFieldName('declarator');
                    const valueNode = declNode.childForFieldName('value');
                    
                    if (nameNode && valueNode?.type === 'call_expression') {
                        const fnName = valueNode.child(0)?.text;
                        const args = valueNode.child(1)?.namedChildren || [];
                        
                        if (fnName === 'malloc' && args.length > 0) {
                            const varName = nameNode.text;
                            const sizeArg = args[0].text;
                        
                            if (/^\d+$/.test(sizeArg)) {
                                // Numerical size
                                const size = parseInt(sizeArg);
                                buffers.set(varName, size);
                        
                                // 🔥 New heap buffer threshold warning
                                if (size > stackThreshold) {
                                    issues.push(`Warning: Large heap buffer "${varName}" (${size} bytes) in "${methodName}" at line ${node.startPosition.row + 1}`);
                                }
                            }
                        
                            mallocAssigned.add(varName);
                        }
                        
                    }
                }
            }
            
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const operator = node.child(1)?.text || '';
                const right = node.child(2);
                
                if (left?.type === 'identifier' && right) {
                    const lhsName = left.text;
                    const rhsText = right.text;
                    
                    // Track aliases
                    if (right.type === 'identifier') {
                        const resolvedRhs = aliases.get(rhsText) || rhsText;
                        
                        if (buffers.has(resolvedRhs) || mallocAssigned.has(resolvedRhs)) {
                            aliases.set(lhsName, resolvedRhs);
                        }
                    }
                    
                    // Track heap allocations
                    if (right.type === 'call_expression') {
                        const fnName = right.child(0)?.text;
                        const args = right.child(1)?.namedChildren || [];
                        
                        if (fnName === 'malloc' && args.length > 0) {
                            const sizeArg = args[0].text;
                        
                            if (/^\d+$/.test(sizeArg)) {
                                // Numerical size
                                const size = parseInt(sizeArg);
                                buffers.set(lhsName, size);
                        
                                //  New heap buffer threshold warning
                                if (size > stackThreshold) {
                                    issues.push(`Warning: Large heap buffer "${lhsName}" (${size} bytes) in "${methodName}" at line ${node.startPosition.row + 1}`);
                                }
                            }
                        
                            mallocAssigned.add(lhsName);
                        }
                        
                    }
                }
            }
            
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text;
                const args = node.child(1)?.namedChildren || [];
                
                if (fnName && unsafeFunctions.has(fnName)) {
                    const safer = unsafeFunctions.get(fnName);
                    issues.push(
                        `Warning: Use of unsafe function "${fnName}" in "${methodName}" at line ${node.startPosition.row + 1}. Consider the safer alternative: "${safer}"`
                    );
                }
                
                // Validation tracking
                if (['strlen', 'sizeof', '_countof'].includes(fnName || '')) {
                    args.forEach(arg => validationChecks.add(arg.text));
                }

                const buffer = args.length > 0 ? args[0].text : null;

                const shouldValidateSize = ['strncpy', 'strncat', 'snprintf', 'memcpy', 'memmove'].includes(fnName || '');

                if (
                    shouldValidateSize &&
                    buffer &&
                    !validationChecks.has(buffer) &&
                    !isValidatedByFunction(buffer) &&
                    !mallocChecked.has(buffer)
                ) {
                    if (fnName === 'strncpy') {
                        const dest = args[0]?.text;
                        const sizeArg = args[2]?.text;
                    
                        const isValidated =
                            validationChecks.has(sizeArg) || /sizeof|strlen/.test(sizeArg);
                    
                        if (!isValidated) {
                            issues.push(
                                `Warning: Unvalidated size parameter in strncpy to "${dest}" in "${methodName}" at line ${node.startPosition.row + 1}`
                            );
                        }
                    
                        if (!validationChecks.has(dest) && !isValidatedByFunction(dest)) {
                            issues.push(
                                `Warning: Possible unsafe usage of "${fnName}" with "${dest}" in "${methodName}" at line ${node.startPosition.row + 1}. Destination is not validated.`
                            );
                        }
                    }
                }

                if (fnName) calledFunctions.add(fnName);
            }

            // NEW: Track subscript_expression nodes for array access validation
            if (node.type === 'subscript_expression') {
                const arrayNode = node.child(0);
                const indexNode = node.child(1);
                
                if (arrayNode?.type === 'identifier' && indexNode) {
                    const arrayName = arrayNode.text;
                    const resolvedArray = aliases.get(arrayName) || arrayName;
                    
                    // Skip if array name is not a known buffer
                    if (!buffers.has(resolvedArray) && !mallocAssigned.has(resolvedArray)) {
                        // Continue with other children
                        node.namedChildren.forEach(child => traverse(child));
                        return;
                    }
                    
                    if (indexNode.type === 'identifier') {
                        const indexVar = indexNode.text;
                        const accessId = `${arrayName}[${indexVar}]_${node.startPosition.row}`;
                        
                        // Store this access for later validation
                        arrayAccesses.set(accessId, {
                            arrayName: resolvedArray,
                            indexVar,
                            node
                        });
                        
                        // Now check if this array access is validated
                        const isLoopValidated = isIndexValidatedByLoop(indexVar, resolvedArray, node);
                        const isExplicitlyValidated = validationChecks.has(indexVar);
                        
                        if (!isLoopValidated && !isExplicitlyValidated) {
                            issues.push(
                                `Warning: Unvalidated index "${indexVar}" used with "${arrayName}" in "${methodName}" at line ${node.startPosition.row + 1}`
                            );
                        }
                    } else if (indexNode.type === 'number_literal') {
                        const indexVal = parseInt(indexNode.text);
                        const bufferSize = buffers.get(resolvedArray);
                        
                        // If buffer size is known and index exceeds it, warn
                        if (bufferSize !== undefined && indexVal >= bufferSize) {
                            issues.push(
                                `Warning: Array index out of bounds: "${arrayName}[${indexVal}]" exceeds buffer size ${bufferSize} in "${methodName}" at line ${node.startPosition.row + 1}`
                            );
                        }
                    }
                }
            }

            // Recurse on children
            node.namedChildren.forEach(child => traverse(child));
        }

        // Fallback: detect numeric validations in conditions like `if (size < 1024)`
        const numericCheckRegex = /\bif\s*\((.*?)\)/gs; // Use `s` flag to allow multiline
        let numericMatch: RegExpExecArray | null;

        while ((numericMatch = numericCheckRegex.exec(methodBody)) !== null) {
            const condition = numericMatch[1];

            // Heuristics: must include number & comparison operator
            if (/[<>!=]=?/.test(condition) && /\b\d+\b/.test(condition)) {
                const varMatches = condition.match(/\b\w+\b/g);
                for (const v of varMatches || []) {
                    if (!['if', 'while', 'for', 'sizeof', 'strlen'].includes(v)) {
                        validationChecks.add(v);
                    }
                }
            }
        }

        traverse(tree.rootNode);

        // NEW: Post-process array accesses to remove warnings for loop-bounded ones
        for (const [accessId, accessInfo] of arrayAccesses) {
            const { arrayName, indexVar, node } = accessInfo;
            
            // If index is validated by a loop, remove any warning about it
            if (isIndexValidatedByLoop(indexVar, arrayName, node)) {
                const lineNum = node.startPosition.row + 1;
                const warningIndex = issues.findIndex(issue => 
                    issue.includes(`Unvalidated index "${indexVar}"`) && 
                    issue.includes(`at line ${lineNum}`)
                );
                
                if (warningIndex !== -1) {
                    issues.splice(warningIndex, 1);
                }
            }
        }

        // Detect hybridized checks like if/while with sizeof/strlen
        const hybridRegex = /(?:\b(?:if|while|for)\s*\(|&&|\|\|).*?\b(?:strlen|sizeof|_countof)\s*\(\s*(\w+)\s*\).*?(?:\)|;)/g;
        let match: RegExpExecArray | null;
        while ((match = hybridRegex.exec(methodBody)) !== null) {
            validationChecks.add(match[1]);
        }

        return issues;
    }
}