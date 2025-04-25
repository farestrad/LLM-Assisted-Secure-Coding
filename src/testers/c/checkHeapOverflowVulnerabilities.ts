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

export class HeapOverflowCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Get configuration values
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const heapFunctions = config.get<string[]>('heapAllocFunctions', [
            'malloc', 'calloc', 'realloc', 'aligned_alloc', 'memalign', 'valloc', 'pvalloc'
        ]);
        const freeFunctions = config.get<string[]>('freeFunctions', [
            'free', 'cfree', 'delete', 'delete[]'
        ]);
        const copyFunctions = config.get<string[]>('memoryCopyFunctions', [
            'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf'
        ]);
        
        // Data structures for tracking variables
        const heapAllocations = new Map<string, {
            allocator: string,
            size: string | null,
            sizeEval: number | null,
            line: number,
            freed: boolean,
            validated: boolean
        }>();
        const freeOperations = new Map<string, { line: number }>();
        const memoryCopyOperations = new Map<string, { 
            source: string, 
            dest: string, 
            size: string, 
            sizeEval: number | null,
            line: number 
        }>();
        const validatedVariables = new Set<string>();
        const variableAliases = new Map<string, Set<string>>(); // original -> Set of aliases
        const integerVariables = new Map<string, { value: number | null, line: number }>();
        const pointerArithmeticOps = new Map<string, { 
            pointer: string, 
            operation: string, 
            operand: string, 
            line: number 
        }>();
        
        // Initialize parser
        initParser();
        const tree = parser.parse(methodBody);
        
        // Helper function to get line number
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }
        
        // Helper function to track heap allocations
        function trackHeapAllocation(variable: string, allocator: string, sizeArg: string | null, line: number) {
            let sizeEval: number | null = null;
            if (sizeArg) {
                // Try to evaluate the size argument
                if (/^\d+$/.test(sizeArg)) {
                    sizeEval = parseInt(sizeArg, 10);
                } else if (integerVariables.has(sizeArg)) {
                    sizeEval = integerVariables.get(sizeArg)?.value || null;
                }
            }
            
            heapAllocations.set(variable, {
                allocator,
                size: sizeArg,
                sizeEval,
                line,
                freed: false,
                validated: false
            });
        }
        
        // Helper function to resolve aliases
        function resolveAlias(varName: string): string {
            // Try to find if varName is an alias
            for (const [original, aliases] of variableAliases.entries()) {
                if (aliases.has(varName)) {
                    return original;
                }
            }
            return varName;
        }
        
        // Helper function to check if a variable has been validated
        function isValidated(varName: string): boolean {
            if (validatedVariables.has(varName)) {
                return true;
            }
            
            // Check if this is an alias of a validated variable
            const resolved = resolveAlias(varName);
            if (resolved !== varName && validatedVariables.has(resolved)) {
                return true;
            }
            
            return false;
        }
        
        // Helper function to evaluate expressions
        function evaluateExpression(expr: string): number | null {
            // Simple numeric literal
            if (/^\d+$/.test(expr)) {
                return parseInt(expr, 10);
            }
            
            // Known integer variable
            if (integerVariables.has(expr)) {
                return integerVariables.get(expr)?.value || null;
            }
            
            // Try to evaluate basic math expressions with known variables
            try {
                // Replace known variables with their values
                const evalExpr = expr.replace(/\b(\w+)\b/g, (match) => {
                    if (integerVariables.has(match)) {
                        const valueObj = integerVariables.get(match);
                        const value = valueObj?.value;
                        return value !== null && value !== undefined ? value.toString() : 'NaN';
                    }
                    return 'NaN'; // Unknown variable
                });
                
                // Only evaluate if all variables were replaced
                if (!evalExpr.includes('NaN')) {
                    // Use safer evaluation
                    const result = Function('"use strict"; return (' + evalExpr + ')')();
                    return typeof result === 'number' ? result : null;
                }
            } catch (e) {
                // Evaluation failed, return null
            }
            
            return null;
        }
        
        // Process AST and fill data structures
        function traverse(node: Parser.SyntaxNode) {
            switch (node.type) {
                case 'declaration': {
                    // Process variable declarations
                    const declNodes = node.descendantsOfType('init_declarator');
                    for (const declNode of declNodes) {
                        const nameNode = declNode.childForFieldName('declarator');
                        const valueNode = declNode.childForFieldName('value');
                        
                        if (nameNode && valueNode) {
                            const name = nameNode.text;
                            const line = getLineNumber(declNode);
                            
                            // Track integer variables
                            if (valueNode.type === 'number_literal') {
                                integerVariables.set(name, {
                                    value: parseInt(valueNode.text, 10),
                                    line
                                });
                            }
                            
                            // Track heap allocations
                            if (valueNode.type === 'call_expression') {
                                const fnName = valueNode.child(0)?.text;
                                const args = valueNode.child(1)?.namedChildren || [];
                                
                                if (heapFunctions.includes(fnName || '')) {
                                    let sizeArg: string | null = null;
                                    
                                    if (fnName === 'malloc' && args.length >= 1) {
                                        sizeArg = args[0].text;
                                    } else if (fnName === 'calloc' && args.length >= 2) {
                                        // calloc(nmemb, size) - multiply the arguments
                                        const nmemb = args[0].text;
                                        const size = args[1].text;
                                        sizeArg = `${nmemb} * ${size}`;
                                    } else if (fnName === 'realloc' && args.length >= 2) {
                                        // Track the original pointer
                                        const origPtr = args[0].text;
                                        if (heapAllocations.has(origPtr)) {
                                            // Mark the original as an alias of the new one
                                            if (!variableAliases.has(name)) {
                                                variableAliases.set(name, new Set());
                                            }
                                            variableAliases.get(name)?.add(origPtr);
                                        }
                                        sizeArg = args[1].text;
                                    }
                                    
                                    trackHeapAllocation(name, fnName || 'unknown', sizeArg, line);
                                    
                                    // Check for integer overflow in allocation size
                                    if (sizeArg) {
                                        const sizeEval = evaluateExpression(sizeArg);
                                        if (sizeEval !== null && sizeEval < 0) {
                                            issues.push(
                                                `Warning: Negative size (${sizeEval}) used in heap allocation at line ${line} in method "${methodName}". This may lead to an integer overflow vulnerability.`
                                            );
                                        } else if (sizeEval !== null && sizeEval === 0) {
                                            issues.push(
                                                `Warning: Zero-size heap allocation at line ${line} in method "${methodName}". This may lead to undefined behavior.`
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                
                case 'assignment_expression': {
                    const left = node.child(0);
                    const operator = node.child(1)?.text || '';
                    const right = node.child(2);
                    
                    if (left?.type === 'identifier' && right) {
                        const varName = left.text;
                        const line = getLineNumber(node);
                        
                        // Track integer variable assignments
                        if (right.type === 'number_literal') {
                            integerVariables.set(varName, {
                                value: parseInt(right.text, 10),
                                line
                            });
                        } else if (right.type === 'binary_expression') {
                            // Try to evaluate binary expressions
                            const exprVal = evaluateExpression(right.text);
                            if (exprVal !== null) {
                                integerVariables.set(varName, {
                                    value: exprVal,
                                    line
                                });
                            }
                        }
                        
                        // Track heap allocations
                        if (right.type === 'call_expression') {
                            const fnName = right.child(0)?.text;
                            const args = right.child(1)?.namedChildren || [];
                            
                            if (heapFunctions.includes(fnName || '')) {
                                let sizeArg: string | null = null;
                                
                                if (fnName === 'malloc' && args.length >= 1) {
                                    sizeArg = args[0].text;
                                } else if (fnName === 'calloc' && args.length >= 2) {
                                    sizeArg = `${args[0].text} * ${args[1].text}`;
                                } else if (fnName === 'realloc' && args.length >= 2) {
                                    const origPtr = args[0].text;
                                    if (heapAllocations.has(origPtr)) {
                                        // Mark the original as an alias of the new one
                                        if (!variableAliases.has(varName)) {
                                            variableAliases.set(varName, new Set());
                                        }
                                        variableAliases.get(varName)?.add(origPtr);
                                    }
                                    sizeArg = args[1].text;
                                }
                                
                                trackHeapAllocation(varName, fnName || 'unknown', sizeArg, line);
                                
                                // Check for integer overflow in allocation size
                                if (sizeArg) {
                                    const sizeEval = evaluateExpression(sizeArg);
                                    if (sizeEval !== null && sizeEval < 0) {
                                        issues.push(
                                            `Warning: Negative size (${sizeEval}) used in heap allocation at line ${line} in method "${methodName}". This may lead to an integer overflow vulnerability.`
                                        );
                                    } else if (sizeEval !== null && sizeEval === 0) {
                                        issues.push(
                                            `Warning: Zero-size heap allocation at line ${line} in method "${methodName}". This may lead to undefined behavior.`
                                        );
                                    }
                                }
                            }
                        }
                        
                        // Track pointer aliases
                        if (right.type === 'identifier') {
                            const rhsName = right.text;
                            
                            // If right side is a heap allocation, track this as an alias
                            if (heapAllocations.has(rhsName)) {
                                if (!variableAliases.has(rhsName)) {
                                    variableAliases.set(rhsName, new Set());
                                }
                                variableAliases.get(rhsName)?.add(varName);
                            }
                        }
                        
                        // Track pointer arithmetic
                        if (operator === '+=' || operator === '-=') {
                            if (heapAllocations.has(varName) || 
                                Array.from(variableAliases.keys()).some(k => variableAliases.get(k)?.has(varName))) {
                                
                                const opId = `${varName}${operator}${right.text}_${line}`;
                                pointerArithmeticOps.set(opId, {
                                    pointer: varName,
                                    operation: operator,
                                    operand: right.text,
                                    line
                                });
                                
                                // Check for unvalidated pointer arithmetic
                                if (!isValidated(varName) && !isValidated(right.text)) {
                                    issues.push(
                                        `Warning: Unvalidated pointer arithmetic at line ${line} in method "${methodName}". Always validate pointer offsets to prevent heap overflow.`
                                    );
                                }
                            }
                        }
                    }
                    break;
                }
                
                case 'binary_expression': {
                    const left = node.child(0);
                    const operator = node.child(1)?.text || '';
                    const right = node.child(2);
                    
                    if (left?.type === 'identifier' && ['+', '-'].includes(operator) && right) {
                        const ptrName = left.text;
                        const line = getLineNumber(node);
                        
                        // Check if this is pointer arithmetic on a heap-allocated buffer
                        if (heapAllocations.has(ptrName) || 
                            Array.from(variableAliases.keys()).some(k => variableAliases.get(k)?.has(ptrName))) {
                            
                            const opId = `${ptrName}${operator}${right.text}_${line}`;
                            pointerArithmeticOps.set(opId, {
                                pointer: ptrName,
                                operation: operator,
                                operand: right.text,
                                line
                            });
                            
                            // Check for unvalidated pointer arithmetic
                            if (!isValidated(ptrName) && !isValidated(right.text)) {
                                issues.push(
                                    `Warning: Unvalidated pointer arithmetic at line ${line} in method "${methodName}". This may lead to heap overflow or underflow.`
                                );
                            }
                            
                            // Check if the offset exceeds allocation size
                            const resolvedPtr = resolveAlias(ptrName);
                            const allocation = heapAllocations.get(resolvedPtr);
                            
                            if (allocation && allocation.sizeEval !== null) {
                                const operandVal = evaluateExpression(right.text);
                                if (operandVal !== null) {
                                    if (operator === '+' && operandVal >= allocation.sizeEval) {
                                        issues.push(
                                            `Warning: Pointer arithmetic at line ${line} in method "${methodName}" may cause heap overflow. Offset ${operandVal} exceeds allocated size ${allocation.sizeEval}.`
                                        );
                                    } else if (operator === '-' && operandVal >= allocation.sizeEval) {
                                        issues.push(
                                            `Warning: Pointer arithmetic at line ${line} in method "${methodName}" may cause heap underflow. Negative offset ${operandVal} is too large.`
                                        );
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                
                case 'if_statement': {
                    // Track validation checks
                    const condition = node.childForFieldName('condition');
                    if (condition) {
                        // Extract all identifiers in the condition
                        const identifiers = condition.descendantsOfType('identifier');
                        for (const id of identifiers) {
                            validatedVariables.add(id.text);
                        }
                        
                        // Check for explicit NULL checks after allocation
                        const conditionText = condition.text;
                        if (conditionText.includes('!=') && conditionText.includes('NULL')) {
                            // This is likely a NULL check, mark all variables in it as validated
                            for (const id of identifiers) {
                                const varName = id.text;
                                if (heapAllocations.has(varName)) {
                                    const allocation = heapAllocations.get(varName);
                                    if (allocation) {
                                        allocation.validated = true;
                                        heapAllocations.set(varName, allocation);
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                
                case 'call_expression': {
                    const fnNameNode = node.child(0);
                    const args = node.child(1)?.namedChildren || [];
                    
                    if (fnNameNode) {
                        const fnName = fnNameNode.text;
                        const line = getLineNumber(node);
                        
                        // Track free operations
                        if (freeFunctions.includes(fnName) && args.length > 0) {
                            const ptrName = args[0].text;
                            freeOperations.set(ptrName, { line });
                            
                            // Mark the original allocation as freed
                            const resolvedPtr = resolveAlias(ptrName);
                            if (heapAllocations.has(resolvedPtr)) {
                                const allocation = heapAllocations.get(resolvedPtr);
                                if (allocation) {
                                    allocation.freed = true;
                                    heapAllocations.set(resolvedPtr, allocation);
                                }
                            }
                        }
                        
                        // Track memory copy operations
                        if (copyFunctions.includes(fnName) && args.length >= 3) {
                            const destPtr = args[0].text;
                            const srcPtr = args[1].text;
                            const sizeArg = args[2].text;
                            const sizeEval = evaluateExpression(sizeArg);
                            
                            const opId = `${fnName}_${line}`;
                            memoryCopyOperations.set(opId, {
                                source: srcPtr,
                                dest: destPtr,
                                size: sizeArg,
                                sizeEval,
                                line
                            });
                            
                            // Check if destination is a heap allocation
                            const resolvedDest = resolveAlias(destPtr);
                            if (heapAllocations.has(resolvedDest)) {
                                const allocation = heapAllocations.get(resolvedDest);
                                
                                // Check for buffer overflow in copy operation
                                if (allocation && allocation.sizeEval !== null && sizeEval !== null) {
                                    if (sizeEval > allocation.sizeEval) {
                                        issues.push(
                                            `Warning: Heap buffer overflow detected at line ${line} in method "${methodName}". Copy size ${sizeEval} exceeds allocated size ${allocation.sizeEval} for buffer "${destPtr}".`
                                        );
                                    }
                                } else if (!isValidated(sizeArg)) {
                                    issues.push(
                                        `Warning: Unvalidated memory copy to heap buffer "${destPtr}" at line ${line} in method "${methodName}". Always validate copy sizes to prevent heap overflow.`
                                    );
                                }
                            }
                        }
                    }
                    break;
                }
                
                case 'subscript_expression': {
                    // FIXED: Proper handling of array access (buffer[index])
                    const array = node.child(0);
                    const index = node.child(1);
                    
                    // Skip if we don't have both array and index parts
                    if (!array || !index) break;
                    
                    // Only process if the array is an identifier
                    if (array.type === 'identifier') {
                        const arrayName = array.text;
                        const line = getLineNumber(node);
                        
                        // Check if this is a heap-allocated buffer
                        const resolvedArray = resolveAlias(arrayName);
                        if (heapAllocations.has(resolvedArray)) {
                            const allocation = heapAllocations.get(resolvedArray);
                            if (!allocation) break; // Safety check
                            
                            // FIXED: Better handling of index expression
                            // Only check if it's a simple identifier or number for now
                            
                            // Skip if the index is a call expression to strcspn
                            if (index.type === 'call_expression') {
                                const callee = index.child(0)?.text;
                                if (callee === 'strcspn') {
                                    // Likely safe use case - no need to warn
                                    break;
                                }
                            }
                            
                            // For identifiers, check if validated
                            if (index.type === 'identifier') {
                                const indexName = index.text;
                                if (!isValidated(indexName)) {
                                    issues.push(
                                        `Warning: Unvalidated array index variable "${indexName}" used with heap-allocated buffer "${arrayName}" at line ${line} in method "${methodName}". Always validate indices to prevent heap overflow.`
                                    );
                                }
                            }
                            // For literals, check bounds
                            else if (index.type === 'number_literal') {
                                const indexVal = parseInt(index.text, 10);
                                if (indexVal < 0) {
                                    issues.push(
                                        `Warning: Negative array index (${indexVal}) used with heap-allocated buffer "${arrayName}" at line ${line} in method "${methodName}". This leads to undefined behavior.`
                                    );
                                } else if (allocation.sizeEval !== null && indexVal >= allocation.sizeEval) {
                                    issues.push(
                                        `Warning: Heap buffer overflow detected at line ${line} in method "${methodName}". Index ${indexVal} exceeds allocated size ${allocation.sizeEval} for buffer "${arrayName}".`
                                    );
                                }
                            }
                            // For expressions, attempt to evaluate
                            else {
                                // Try to get meaningful text from the index node
                                const indexText = index.text.replace(/^\[|\]$/g, '').trim();
                                
                                // Skip if the index is empty or just syntax characters
                                if (!indexText || /^[\[\]\(\){}]$/.test(indexText)) {
                                    break;
                                }
                                
                                const indexVal = evaluateExpression(indexText);
                                if (indexVal !== null) {
                                    if (indexVal < 0) {
                                        issues.push(
                                            `Warning: Negative array index (${indexVal}) used with heap-allocated buffer "${arrayName}" at line ${line} in method "${methodName}". This leads to undefined behavior.`
                                        );
                                    } else if (allocation.sizeEval !== null && indexVal >= allocation.sizeEval) {
                                        issues.push(
                                            `Warning: Heap buffer overflow detected at line ${line} in method "${methodName}". Index ${indexVal} exceeds allocated size ${allocation.sizeEval} for buffer "${arrayName}".`
                                        );
                                    }
                                } else if (!isValidated(indexText)) {
                                    issues.push(
                                        `Warning: Unvalidated array index expression "${indexText}" used with heap-allocated buffer "${arrayName}" at line ${line} in method "${methodName}". Always validate indices to prevent heap overflow.`
                                    );
                                }
                            }
                        }
                    }
                    break;
                }
                
                case 'unary_expression': {
                    // Check for pointer dereference (*ptr)
                    if (node.text.startsWith('*')) {
                        const operand = node.child(0);
                        if (operand?.type === 'identifier') {
                            const ptrName = operand.text;
                            const line = getLineNumber(node);
                            
                            // Check if this is dereferencing a heap-allocated buffer
                            const resolvedPtr = resolveAlias(ptrName);
                            if (heapAllocations.has(resolvedPtr)) {
                                const allocation = heapAllocations.get(resolvedPtr);
                                
                                // Check if dereferencing freed memory
                                if (allocation && allocation.freed) {
                                    issues.push(
                                        `Warning: Use-after-free vulnerability detected at line ${line} in method "${methodName}". Dereferencing pointer "${ptrName}" after it has been freed.`
                                    );
                                }
                                
                                // Check if pointer has been validated
                                if (!allocation?.validated && !isValidated(ptrName)) {
                                    issues.push(
                                        `Warning: Dereferencing potentially NULL pointer "${ptrName}" at line ${line} in method "${methodName}". Always check heap allocations for NULL before use.`
                                    );
                                }
                            }
                        }
                    }
                    break;
                }
            }
            
            // Recursive traversal
            node.namedChildren.forEach(child => traverse(child));
        }
        
        // Start traversal
        traverse(tree.rootNode);
        
        return issues;
    }
}