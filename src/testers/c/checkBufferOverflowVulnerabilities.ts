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
        
        // Check if an index is validated by a loop condition
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
        
        // NEW: Check for potential off-by-one errors in loop conditions
        function checkOffByOneInLoop(loopVar: string, maxBound: number | null, operator: string, 
                                     bufferName: string | null, bufferSize: number | null, 
                                     node: Parser.SyntaxNode): boolean {
            // If we don't have buffer size or max bound, we can't check
            if (maxBound === null || bufferSize === null || !bufferName) return false;
            
            const line = node.startPosition.row + 1;
            
            // Check for typical off-by-one scenarios
            if (operator === '<=' && maxBound === bufferSize) {
                issues.push(
                    `Warning: Potential off-by-one error in loop condition at line ${line} in method "${methodName}". Loop uses '<=' with buffer size ${bufferSize} for variable "${loopVar}" accessing buffer "${bufferName}". The last valid index is ${bufferSize-1}.`
                );
                return true;
            }
            
            if (operator === '<' && maxBound === bufferSize+1) {
                issues.push(
                    `Warning: Potential off-by-one error in loop condition at line ${line} in method "${methodName}". Loop bound ${maxBound} is one more than necessary for buffer "${bufferName}" of size ${bufferSize}.`
                );
                return true;
            }
            
            return false;
        }

        function traverse(node: Parser.SyntaxNode) {
            if (visited.has(node)) return;
            visited.add(node);
            
            if (node.type === 'declaration') {
                const declarators = node.descendantsOfType('array_declarator');
                
                for (const declarator of declarators) {
                    const nameNode = declarator.descendantsOfType('identifier')[0];
                    const sizeNode = declarator.descendantsOfType('number_literal')[0];
            
                    if (nameNode && sizeNode) {
                        const name = nameNode.text;
                        const size = parseInt(sizeNode.text);
                        buffers.set(name, size);
            
                        if (size > stackThreshold) {
                            issues.push(`Warning: Large stack buffer "${name}" (${size} bytes) in "${methodName}" at line ${node.startPosition.row + 1}`);
                        }
            
                        
                    }
                }
            }
            
            
            // Track loop variables and their bounds
            if (node.type === 'for_statement') {
                // 1. Extract initialization (e.g., int i = 0)
                const initNode = node.childForFieldName('initializer');
                
                // 2. Extract condition (e.g., i < 100)
                const conditionNode = node.childForFieldName('condition');
                
                // 3. Extract the loop variable and its bounds
                let loopVar: string | null = null;
                let minBound: number | null = null;
                let maxBound: number | null = null;
                let condOperator: string = '';
                
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
                        rightNode) {
                        
                        // Only set loopVar if we didn't get it from initialization
                        loopVar = loopVar || leftNode.text;
                        condOperator = opNode?.text || '';
                        
                        if (rightNode.type === 'number_literal') {
                            maxBound = parseInt(rightNode.text);
                            
                            // Check if this is a loop over an array and detect array size
                            const lineNum = node.startPosition.row + 1;
                            const comparisonValue = maxBound;
                            
                            // Look for arrays in this scope that might be related to this loop
                            for (const [bufferName, bufferSize] of buffers.entries()) {
                                // If the comparison value matches the array size, this could be off-by-one
                                if (opNode?.text === '<=' && comparisonValue === bufferSize) {
                                    issues.push(
                                        `Warning: Off-by-one error detected at line ${lineNum} in method "${methodName}". Loop condition "i <= ${bufferSize}" will access array "${bufferName}" out of bounds. Last valid index is ${bufferSize-1}.`
                                    );
                                }
                            }
                            
                            // Adjust for <= operator
                            if (opNode?.text === '<=') {
                                maxBound += 1;
                            }
                        } else if (rightNode.type === 'identifier') {
                            // The loop bound is a variable - check if it's a buffer size
                            const boundVar = rightNode.text;
                            
                            // NEW: Check for potential off-by-one errors in loop conditions that use buffer sizes
                            if (buffers.has(boundVar)) {
                                // The loop is iterating up to a buffer's size
                                const bufferSize = buffers.get(boundVar)!;
                                maxBound = opNode?.text === '<' ? bufferSize : bufferSize + 1;
                                
                                // Check for off-by-one when accessing buffer with this loop
                                const offByOneFound = checkOffByOneInLoop(
                                    loopVar, 
                                    maxBound, 
                                    condOperator,
                                    boundVar,
                                    bufferSize,
                                    node
                                );
                                
                                // Add specific warning for using <= with array size
                                if (opNode?.text === '<=') {
                                    issues.push(
                                        `Warning: Off-by-one error detected at line ${node.startPosition.row + 1} in method "${methodName}". Loop condition "${loopVar} <= ${boundVar}" can access array out of bounds. The last valid index is ${bufferSize-1}.`
                                    );
                                }
                            } else {
                                // If it's not directly a buffer size, it might be a related variable
                                // Check common patterns like "length" or "size" variables
                                for (const [bufName, bufSize] of buffers.entries()) {
                                    if (boundVar === `${bufName}_len` || 
                                        boundVar === `${bufName}_size` || 
                                        boundVar === `${bufName}Length` || 
                                        boundVar === `${bufName}Size`) {
                                        
                                        // Check for off-by-one with this derived size variable
                                        const offByOneFound = checkOffByOneInLoop(
                                            loopVar, 
                                            maxBound, 
                                            condOperator,
                                            bufName,
                                            bufSize,
                                            node
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        
                        // NEW: Check for off-by-one errors in condition structure
                        // For example: for(i=0; i <= len; i++) is often an off-by-one error
                        // when len represents the length of an array
                        if (maxBound !== null && condOperator === '<=') {
                            // Look for array accesses inside the loop body
                            const bodyNode = node.childForFieldName('body');
                            if (bodyNode) {
                                // Analyze the body to see if this loop variable is used to access arrays
                                let foundArrayAccess = false;
                                let accessedArray = '';
                                
                                function findArrayAccesses(n: Parser.SyntaxNode) {
                                    if (n.type === 'subscript_expression') {
                                        const arrayNode = n.child(0);
                                        const indexNode = n.child(1);
                                        
                                        if (indexNode?.type === 'identifier' && 
                                            indexNode.text === loopVar && 
                                            arrayNode?.type === 'identifier') {
                                            
                                            foundArrayAccess = true;
                                            accessedArray = arrayNode.text;
                                        }
                                    }
                                    
                                    for (const child of n.namedChildren) {
                                        findArrayAccesses(child);
                                    }
                                }
                                
                                findArrayAccesses(bodyNode);
                                
                                if (foundArrayAccess && buffers.has(accessedArray)) {
                                    const arraySize = buffers.get(accessedArray)!;
                                    
                                    // If the loop goes to <= array length, it's an off-by-one error
                                    if (maxBound > arraySize && maxBound <= arraySize + 1) {
                                        issues.push(
                                            `Warning: Potential off-by-one error at line ${node.startPosition.row + 1} in method "${methodName}". Loop uses condition "${loopVar} <= ${maxBound-1}" when accessing array "${accessedArray}" of size ${arraySize}. The last valid index is ${arraySize-1}.`
                                        );
                                    }
                                }
                            }
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
            
            if (node.type === 'init_declarator') {
                const declaratorNode = node.childForFieldName('declarator');
                const valueNode = node.childForFieldName('value');
                
                if (declaratorNode?.type === 'identifier' && valueNode?.type === 'call_expression') {
                    const fnName = valueNode.child(0)?.text;
                    const args = valueNode.child(1)?.namedChildren || [];
                    
                    if (fnName === 'malloc' && args.length > 0) {
                        const varName = declaratorNode.text;
                        const sizeArg = args[0].text;
                    
                        if (/^\d+$/.test(sizeArg)) {
                            // Numerical size
                            const size = parseInt(sizeArg);
                            buffers.set(varName, size);
                    
                            // Heap buffer threshold warning
                            if (size > stackThreshold) {
                                issues.push(`Warning: Large heap buffer "${varName}" (${size} bytes) in "${methodName}" at line ${node.startPosition.row + 1}`);
                            }
                        }
                    
                        mallocAssigned.add(varName);
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
                
                // NEW: Check for off-by-one errors in string functions
                if (fnName === 'strncpy' || fnName === 'memcpy' || fnName === 'memmove') {
                    const destArg = args[0]?.text;
                    const sizeArg = args[2];
                    
                    if (destArg && sizeArg && buffers.has(destArg)) {
                        const bufSize = buffers.get(destArg)!;
                        
                        if (sizeArg.type === 'number_literal') {
                            const copySize = parseInt(sizeArg.text);
                            
                            // If copy size is exactly the buffer size, this is likely an off-by-one error
                            // for null-terminated strings
                            if (copySize === bufSize && fnName === 'strncpy') {
                                issues.push(
                                    `Warning: Potential off-by-one error at line ${node.startPosition.row + 1} in method "${methodName}". Using size ${copySize} with strncpy to buffer "${destArg}" of same size ${bufSize} leaves no room for null terminator.`
                                );
                            }
                        } else if (sizeArg.type === 'identifier') {
                            // If size arg is the same as the buffer size variable, it might be an off-by-one
                            for (const [bufName, size] of buffers.entries()) {
                                if (sizeArg.text === `${bufName}_len` || 
                                    sizeArg.text === `${bufName}_size` || 
                                    sizeArg.text === `${bufName}Length` || 
                                    sizeArg.text === `${bufName}Size`) {
                                    
                                    if (bufName === destArg && fnName === 'strncpy') {
                                        issues.push(
                                            `Warning: Potential off-by-one error at line ${node.startPosition.row + 1} in method "${methodName}". Using buffer's size directly with strncpy may leave no room for null terminator.`
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                if (fnName) calledFunctions.add(fnName);
            }

            // Track subscript_expression nodes for array access validation
            if (node.type === 'subscript_expression') {
                const arrayNode = node.child(0);
                const indexNode = node.child(1);
                
                if (arrayNode?.type === 'identifier' && indexNode) {
                    const arrayName = arrayNode.text;
                    const resolvedArray = aliases.get(arrayName) || arrayName;
                    
                    // Get the buffer size if known
                    const bufferSize = buffers.get(resolvedArray);
                    
                    // Check for array access with a constant index that's out of bounds
                    if (indexNode.type === 'number_literal') {
                        const indexVal = parseInt(indexNode.text);
                        
                        // If buffer size is known, check for out-of-bounds access
                        if (bufferSize !== undefined) {
                            // Clear out-of-bounds access
                            if (indexVal >= bufferSize) {
                                console.log("Buffers:", [...buffers.entries()]);

                                issues.push(
                                    `Warning: Array index out of bounds: "${arrayName}[${indexVal}]" exceeds buffer size ${bufferSize} in "${methodName}" at line ${node.startPosition.row + 1}. Valid indices are 0 to ${bufferSize-1}.`
                                );
                            }
                            
                            // NEW: Specific check for off-by-one pattern where index is exactly bufferSize-1
                            if (indexVal === bufferSize - 1) {
                                // This is right at the boundary - might be intentional, but flag if it's used in
                                // a memory-intensive operation
                                const parent = node.parent;
                                if (parent?.type === 'assignment_expression' && parent.child(0) === node) {
                                    issues.push(
                                        `Warning: Potential off-by-one vulnerability at line ${node.startPosition.row + 1} in method "${methodName}". Writing to last element "${arrayName}[${indexVal}]" (size ${bufferSize}). Verify this is intentional.`
                                    );
                                }
                            }
                        }
                    }
                    
                    // Skip the rest of this block if array name is not a known buffer
                    if (!buffers.has(resolvedArray) && !mallocAssigned.has(resolvedArray)) {
                        // Continue with other children
                        node.namedChildren.forEach(child => traverse(child));
                        return;
                    }
                    
                    // NEW: Specifically check for the buffer[size] off-by-one error pattern
                    if (indexNode.type === 'identifier' && buffers.has(resolvedArray)) {
                        const indexVar = indexNode.text;
                        const bufferSize = buffers.get(resolvedArray)!;
                        
                        // Check if the indexVar is equal to bufferSize or bufferSize-1
                        if (indexVar === `${resolvedArray}_size` || 
                            indexVar === `${resolvedArray}_len` ||
                            indexVar === `${resolvedArray}Size` ||
                            indexVar === `${resolvedArray}Length`) {
                            
                            issues.push(
                                `Warning: Potential off-by-one error at line ${node.startPosition.row + 1} in method "${methodName}". Accessing "${arrayName}" with its size as index. Arrays are 0-indexed, so valid indices are 0 to size-1.`
                            );
                        }
                        
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
                    } else if (indexNode.type === 'binary_expression') {
                        // Check for patterns like array[i+1] where i is a loop variable
                        const left = indexNode.child(0);
                        const op = indexNode.child(1)?.text;
                        const right = indexNode.child(2);
                        
                        if (left?.type === 'identifier' && op === '+' && right?.type === 'number_literal') {
                            const loopVar = left.text;
                            const offset = parseInt(right.text);
                            
                            // If this is a loop variable and we know its bounds
                            if (loopVariables.has(loopVar)) {
                                const loopInfo = loopVariables.get(loopVar)!;
                                const maxBound = loopInfo.max;
                                
                                // If we know the buffer size and max loop bound
                                if (buffers.has(resolvedArray) && maxBound !== null) {
                                    const bufferSize = buffers.get(resolvedArray)!;
                                    
                                    // Check if the max index (maxBound-1+offset) would exceed buffer bounds
                                    if (maxBound - 1 + offset >= bufferSize) {
                                        issues.push(
                                            `Warning: Potential off-by-one error at line ${node.startPosition.row + 1} in method "${methodName}". Expression "${loopVar}+${offset}" can access out of bounds of "${arrayName}" (size ${bufferSize}).`
                                        );
                                    }
                                }
                            }
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

        // Post-process array accesses to remove warnings for loop-bounded ones
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