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

export class InfiniteLoopCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Get loop detection configuration
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const detectionLevel = config.get<string>('infiniteLoopDetectionLevel', 'moderate');
        const memoryThreshold = config.get<number>('excessiveMemoryThreshold', 1024 * 1024); // Default: 1MB
        
        // Known C constants to exclude from variable checks
        const knownConstants = new Set([
            'NULL', 'EOF', 'SEEK_SET', 'SEEK_CUR', 'SEEK_END',
            'true', 'false', 'TRUE', 'FALSE'
        ]);
        
        // Context tracking for better analysis
        const context = {
            loopContexts: new Map<string, {
                node: Parser.SyntaxNode,
                variables: Set<string>,
                controlVariables: Set<string>, // NEW: Explicitly track loop control variables
                modifiedVars: Set<string>,
                hasBreak: boolean,
                hasReturn: boolean,
                hasExit: boolean,
                hasThrow: boolean,
                hasContinue: boolean,
                hasGoTo: boolean,
                hasFunctionCall: boolean,
                isTicking: boolean    // Clock/timer-based loop that likely ends
            }>(),
            functionCalls: new Set<string>(),
            fileOperations: new Set<string>(),
            allocations: new Map<string, number>(),
            flaggedLoops: new Set<string>()
        };
        
        // Generate unique node ID
        function nodeKey(node: Parser.SyntaxNode): string {
            return `${node.type}-${node.startPosition.row}:${node.startPosition.column}`;
        }
        
        // Add line number info to warnings
        function formatLineInfo(node: Parser.SyntaxNode): string {
            return `line ${node.startPosition.row + 1}`;
        }
        
        // NEW: Check if a node is a function call
        function isFunctionCall(node: Parser.SyntaxNode): boolean {
            return node.type === 'call_expression';
        }
        
        // NEW: Check if a string is a known constant
        function isConstant(name: string): boolean {
            return knownConstants.has(name) || /^[A-Z][A-Z0-9_]*$/.test(name);
        }
        
        // NEW: Improved variable extraction from condition expressions
        function extractVariablesFromCondition(conditionNode: Parser.SyntaxNode | null): {
            variables: Set<string>,
            controlVariables: Set<string> // Variables that control the loop
        } {
            const variables = new Set<string>();
            const controlVariables = new Set<string>();
            
            if (!conditionNode) return { variables, controlVariables };
            
            // Helper to determine if a variable is likely a loop control variable
            function isLikelyControlVariable(node: Parser.SyntaxNode, varName: string): boolean {
                // If parent is a binary expression like "i < 10", then i is a control variable
                if (node.parent?.type === 'binary_expression') {
                    const binExpr = node.parent;
                    const operator = binExpr.child(1)?.text;
                    
                    // Comparison operators suggest this is a control variable
                    if (['<', '>', '<=', '>=', '==', '!='].includes(operator || '')) {
                        // The variable being compared is likely a control variable
                        if (binExpr.child(0) === node) {
                            return true;
                        }
                    }
                }
                
                return false;
            }
            
            function collectIdentifiers(node: Parser.SyntaxNode) {
                // Skip function calls - don't count their names as variables
                if (isFunctionCall(node)) {
                    // Only process arguments, not the function name
                    const args = node.child(1);
                    if (args) {
                        args.children.forEach(collectIdentifiers);
                    }
                    return;
                }
                
                if (node.type === 'identifier') {
                    const varName = node.text;
                    
                    // Skip constants and standard library functions
                    if (isConstant(varName) || 
                        ['getchar', 'fgetc', 'getc', 'scanf', 'fscanf'].includes(varName)) {
                        return;
                    }
                    
                    variables.add(varName);
                    
                    // Check if this is likely a control variable
                    if (isLikelyControlVariable(node, varName)) {
                        controlVariables.add(varName);
                    }
                }
                
                node.children.forEach(collectIdentifiers);
            }
            
            collectIdentifiers(conditionNode);
            
            // For for-loops, extract the loop control variable from initializer
            if (conditionNode.parent?.type === 'for_statement') {
                const forStatement = conditionNode.parent;
                const initializer = forStatement.childForFieldName('initializer');
                
                if (initializer) {
                    if (initializer.type === 'declaration') {
                        // e.g., for (int i = 0; ...)
                        const declarators = initializer.descendantsOfType('init_declarator');
                        for (const decl of declarators) {
                            const nameNode = decl.childForFieldName('declarator');
                            if (nameNode) {
                                const controlVar = nameNode.text;
                                controlVariables.add(controlVar);
                            }
                        }
                    } else if (initializer.type === 'assignment_expression') {
                        // e.g., for (i = 0; ...)
                        const lhs = initializer.child(0);
                        if (lhs && lhs.type === 'identifier') {
                            const controlVar = lhs.text;
                            controlVariables.add(controlVar);
                        }
                    }
                }
            }
            
            return { variables, controlVariables };
        }
        
        // Check if a loop contains any termination statements
        function hasTerminationStatements(node: Parser.SyntaxNode): {
            hasBreak: boolean,
            hasReturn: boolean,
            hasExit: boolean,
            hasThrow: boolean,
            hasContinue: boolean,
            hasGoTo: boolean,
            hasFunctionCall: boolean
        } {
            const result = {
                hasBreak: false,
                hasReturn: false,
                hasExit: false,
                hasThrow: false,
                hasContinue: false,
                hasGoTo: false,
                hasFunctionCall: false
            };
            
            function check(n: Parser.SyntaxNode) {
                // Don't check inside nested loops
                if (n !== node && (
                    n.type === 'for_statement' || 
                    n.type === 'while_statement' || 
                    n.type === 'do_statement'
                )) {
                    return;
                }
                
                if (n.type === 'break_statement') {
                    result.hasBreak = true;
                } else if (n.type === 'return_statement') {
                    result.hasReturn = true;
                } else if (n.type === 'throw_statement') {
                    result.hasThrow = true;
                } else if (n.type === 'continue_statement') {
                    result.hasContinue = true;
                } else if (n.type === 'goto_statement') {
                    result.hasGoTo = true;
                } else if (n.type === 'call_expression') {
                    const fnName = n.child(0)?.text || '';
                    // Check for exit-like functions
                    if (/exit|abort|terminate|longjmp|_Exit/.test(fnName)) {
                        result.hasExit = true;
                    }
                    
                    // Track function calls which may contain logic to end the loop
                    result.hasFunctionCall = true;
                }
                
                n.children.forEach(check);
            }
            
            check(node);
            return result;
        }
        
        // Improved tracking of modified variables in a block
        function trackModifiedVariables(node: Parser.SyntaxNode, targetVars: Set<string>): Set<string> {
            const modifiedVars = new Set<string>();
            
            function check(n: Parser.SyntaxNode) {
                // Handle different types of variable modifications
                
                // 1. Increment/decrement expressions (i++, --j)
                if (n.type === 'update_expression') {
                    const varNode = n.child(0);
                    if (varNode && varNode.type === 'identifier' && targetVars.has(varNode.text)) {
                        modifiedVars.add(varNode.text);
                    }
                }
                
                // 2. Direct assignments (i = 5)
                else if (n.type === 'assignment_expression') {
                    const lhs = n.child(0);
                    if (lhs && lhs.type === 'identifier' && targetVars.has(lhs.text)) {
                        modifiedVars.add(lhs.text);
                    }
                }
                
                // 3. Compound assignments (i += 1, j *= 2)
                else if (n.type === 'compound_assignment_expression' || n.type === 'augmented_assignment_expression') {
                    const lhs = n.child(0);
                    if (lhs && lhs.type === 'identifier' && targetVars.has(lhs.text)) {
                        modifiedVars.add(lhs.text);
                    }
                }
                
                // 4. Function calls that might modify variables by pointer
                else if (n.type === 'call_expression') {
                    const args = n.child(1)?.children || [];
                    
                    // Check for pass-by-reference args 
                    for (const arg of args) {
                        // Look for address-of operator on variables
                        if (arg.type === 'unary_expression' && arg.text.startsWith('&')) {
                            const varNode = arg.child(0);
                            if (varNode && varNode.type === 'identifier' && targetVars.has(varNode.text)) {
                                modifiedVars.add(varNode.text);
                            }
                        }
                    }
                }
                
                n.children.forEach(check);
            }
            
            check(node);
            return modifiedVars;
        }
        
        // Extract variables that are incremented in a for loop update expression
        function extractForIncrements(node: Parser.SyntaxNode): Set<string> {
            const updateVars = new Set<string>();
            const updateNode = node.childForFieldName('update');
            
            if (!updateNode) return updateVars;
            
            function collect(n: Parser.SyntaxNode) {
                if (n.type === 'update_expression') {
                    const varNode = n.child(0);
                    if (varNode && varNode.type === 'identifier') {
                        updateVars.add(varNode.text);
                    }
                }
                else if (n.type === 'assignment_expression' || n.type === 'augmented_assignment_expression') {
                    const lhs = n.child(0);
                    if (lhs && lhs.type === 'identifier') {
                        updateVars.add(lhs.text);
                    }
                }
                
                n.children.forEach(collect);
            }
            
            collect(updateNode);
            return updateVars;
        }
        
        // Check if a loop is likely a timer/event-based wait loop
        function isTimeBasedWaitLoop(conditionNode: Parser.SyntaxNode | null, bodyNode: Parser.SyntaxNode | null): boolean {
            if (!conditionNode || !bodyNode) return false;
            
            // Check for common time-based loop patterns
            
            // 1. Check for timer/clock functions in body
            const bodyText = bodyNode.text.toLowerCase();
            const hasTimerFunctions = /\b(sleep|usleep|nanosleep|delay|wait|timeout|yield|clock|timer|pthread_cond_wait)\b/.test(bodyText);
            
            // 2. Check for time-based variables in condition
            const conditionText = conditionNode.text.toLowerCase();
            const hasTimeCondition = /\b(timer|clock|time|timeout|elapsed|duration|millisecond|second|tick|counter)\b/.test(conditionText);
            
            return hasTimerFunctions || hasTimeCondition;
        }
        
        // Check if a loop contains excessive allocations
        function hasExcessiveMemoryUsage(node: Parser.SyntaxNode): boolean {
            let excessiveAllocation = false;
            
            function check(n: Parser.SyntaxNode) {
                if (n.type === 'call_expression') {
                    const fnName = n.child(0)?.text || '';
                    
                    // Check memory allocation functions
                    if (/\b(malloc|calloc|realloc)\b/.test(fnName)) {
                        const argList = n.child(1);
                        if (!argList) return;
                        
                        // Extract size arguments
                        if (fnName === 'malloc' || fnName === 'realloc') {
                            // Single size argument
                            const sizeArg = argList.namedChildren[fnName === 'realloc' ? 1 : 0];
                            if (sizeArg && sizeArg.type === 'number_literal') {
                                const size = parseInt(sizeArg.text, 10);
                                if (size > memoryThreshold) {
                                    excessiveAllocation = true;
                                }
                            }
                        } 
                        else if (fnName === 'calloc') {
                            // Two arguments: count and size
                            const countArg = argList.namedChildren[0];
                            const sizeArg = argList.namedChildren[1];
                            
                            if (countArg && sizeArg && 
                                countArg.type === 'number_literal' && 
                                sizeArg.type === 'number_literal') {
                                const count = parseInt(countArg.text, 10);
                                const size = parseInt(sizeArg.text, 10);
                                if (count * size > memoryThreshold) {
                                    excessiveAllocation = true;
                                }
                            }
                        }
                    }
                }
                
                n.children.forEach(check);
            }
            
            check(node);
            return excessiveAllocation;
        }
        
        // NEW: Improved check for always-true conditions
        function isAlwaysTrueCondition(conditionNode: Parser.SyntaxNode | null): boolean {
            if (!conditionNode) return true;
        
            // Case: direct number literal like `1`
            if (conditionNode.type === 'number_literal' && conditionNode.text.trim() === '1') {
                return true;
            }
        
            // Case: (1) or (!0) wrapped in a parenthesized_expression
            if (conditionNode.type === 'parenthesized_expression') {
                const inner = conditionNode.namedChildren[0];
                if (inner?.type === 'number_literal' && inner.text.trim() === '1') {
                    return true;
                }
                if (inner?.type === 'unary_expression' && inner.text.trim() === '!0') {
                    return true;
                }
            }
        
            // Check tautologies like (1 == 1)
            if (conditionNode.type === 'binary_expression') {
                const op = conditionNode.child(1)?.text;
                const lhs = conditionNode.child(0);
                const rhs = conditionNode.child(2);
        
                if (lhs?.type === 'number_literal' && rhs?.type === 'number_literal') {
                    const l = parseInt(lhs.text, 10);
                    const r = parseInt(rhs.text, 10);
        
                    if (op === '==' && l === r) return true;
                    if (op === '<=' && l <= r) return true;
                    if (op === '>=' && l >= r) return true;
                }
            }
            
            // NEW: Check for while(1), while(true), etc.
            if (conditionNode.type === 'identifier') {
                return conditionNode.text === 'true' || conditionNode.text === 'TRUE';
            }
        
            return false;
        }
        
        // NEW: Check if the condition includes function calls that might change its value
        function conditionHasFunctionCalls(conditionNode: Parser.SyntaxNode | null): boolean {
            if (!conditionNode) return false;
            
            let hasFunctionCall = false;
            
            function checkForCalls(node: Parser.SyntaxNode) {
                if (node.type === 'call_expression') {
                    hasFunctionCall = true;
                    return; // Stop traversal once found
                }
                
                // Continue checking children if no call found yet
                if (!hasFunctionCall) {
                    node.children.forEach(checkForCalls);
                }
            }
            
            checkForCalls(conditionNode);
            return hasFunctionCall;
        }
        
        // Process the AST to find loops and other relevant nodes
        initParser();
        const tree = parser.parse(methodBody);
        
        // Main loop analysis function
        function analyzeLoop(node: Parser.SyntaxNode, inheritedModifiedVars: Set<string> = new Set<string>()) {
            // Only analyze loops once
            const key = nodeKey(node);
            if (context.flaggedLoops.has(key)) {
                return;
            }
            
            // Mark as processed
            context.flaggedLoops.add(key);
            
            // Get condition node based on loop type
            let conditionNode: Parser.SyntaxNode | null = null;
            
            if (node.type === 'for_statement') {
                conditionNode = node.childForFieldName('condition');
            } 
            else if (node.type === 'while_statement') {
                conditionNode = node.childForFieldName('condition');
            } 
            else if (node.type === 'do_statement') {
                conditionNode = node.childForFieldName('condition');
            }
            
            const bodyNode = node.childForFieldName('body');
            
            // Extract variables used in the condition
            const { variables: conditionVars, controlVariables } = extractVariablesFromCondition(conditionNode);
            
            // Check for loop termination statements
            const terminationInfo = bodyNode ? hasTerminationStatements(bodyNode) : {
                hasBreak: false,
                hasReturn: false,
                hasExit: false,
                hasThrow: false,
                hasContinue: false,
                hasGoTo: false,
                hasFunctionCall: false
            };
            
            // Track variables modified in the body
            const bodyModifiedVars = bodyNode ? trackModifiedVariables(bodyNode, conditionVars) : new Set<string>();
            
            // For 'for' loops, capture update expression variables
            const forUpdateVars = node.type === 'for_statement' 
                ? extractForIncrements(node) 
                : new Set<string>();
            
            // Combine all modified variables
            const totalModifiedVars = new Set<string>([
                ...Array.from(inheritedModifiedVars),
                ...Array.from(bodyModifiedVars),
                ...Array.from(forUpdateVars)
            ]);
            
            // Check if this is a timing/waiting loop
            const isWaitLoop = conditionNode && bodyNode ? isTimeBasedWaitLoop(conditionNode, bodyNode) : false;
            
            // NEW: Check if condition contains function calls that can change its value
            const hasDynamicCondition = conditionHasFunctionCalls(conditionNode);
            
            // Check for excessive memory allocations
            const hasExcessiveMemory = bodyNode ? hasExcessiveMemoryUsage(bodyNode) : false;
            
            // Store context for this loop
            context.loopContexts.set(key, {
                node,
                variables: conditionVars,
                controlVariables, // NEW: store the identified control variables
                modifiedVars: totalModifiedVars,
                ...terminationInfo,
                isTicking: isWaitLoop
            });
            
            // Perform infinite loop checks
            
            // 1. Check for explicit infinite loops
            if (isAlwaysTrueCondition(conditionNode)) {
                // Only warn if no break/return/exit paths found, unless in strict mode
                if (detectionLevel === 'strict' || 
                    (!terminationInfo.hasBreak && 
                     !terminationInfo.hasReturn && 
                     !terminationInfo.hasExit &&
                     !terminationInfo.hasThrow)) {
                    issues.push(
                        `Warning: Potential infinite '${node.type.replace('_statement', '')}' loop in method "${methodName}" at ${formatLineInfo(node)}. Loop has an always-true condition and may not terminate.`
                    );
                }
            }
            
            // 2. Check for condition variables that aren't modified - IMPROVED LOGIC
            else {
                // NEW: Only check control variables, not all condition variables
                const unmodifiedControlVars = Array.from(controlVariables)
                    .filter(varName => !totalModifiedVars.has(varName));
                
                // Skip warning if:
                // - All control variables are modified, or
                // - There are termination statements, or
                // - It's a timing/wait loop, or
                // - The condition includes function calls that might change its value
                if (unmodifiedControlVars.length > 0 && 
                    !terminationInfo.hasBreak && 
                    !terminationInfo.hasReturn && 
                    !terminationInfo.hasExit &&
                    !terminationInfo.hasThrow &&
                    !isWaitLoop &&
                    !hasDynamicCondition) {
                        
                    issues.push(
                        `Warning: Loop control variable(s) [${unmodifiedControlVars.join(', ')}] never modified in method "${methodName}" at ${formatLineInfo(node)}. This may result in an infinite loop.`
                    );
                }
            }
            
            // 3. Check for excessive memory usage
            if (hasExcessiveMemory && (detectionLevel !== 'relaxed')) {
                issues.push(
                    `Warning: Loop at ${formatLineInfo(node)} in method "${methodName}" contains excessive memory allocations which may lead to resource exhaustion.`
                );
            }
            
            // Continue traversing the AST
            node.namedChildren.forEach(child => traverse(child, totalModifiedVars));
        }
        
        // Main AST traversal function
        function traverse(node: Parser.SyntaxNode, inheritedModifiedVars: Set<string> = new Set<string>()) {
            // Handle different node types
            
            // Loop statements
            if (node.type === 'for_statement' ||
                node.type === 'while_statement' ||
                node.type === 'do_statement') {
                analyzeLoop(node, inheritedModifiedVars);
                
                // Skip further traversal since analyzeLoop() already handles recursion
                return;
            }
            
            // Check for excessive memory allocations outside loops
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                
                if (/malloc|calloc|realloc/.test(fnName)) {
                    const argList = node.child(1);
                    
                    if (argList) {
                        // Different handling based on function
                        if (fnName === 'malloc' || fnName === 'realloc') {
                            const sizeArg = argList.namedChildren[fnName === 'realloc' ? 1 : 0];
                            
                            if (sizeArg && sizeArg.type === 'number_literal') {
                                const size = parseInt(sizeArg.text, 10);
                                if (size > memoryThreshold) {
                                    issues.push(
                                        `Warning: Excessive memory allocation (${size} bytes) using "${fnName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                                    );
                                }
                            }
                        } 
                        else if (fnName === 'calloc') {
                            const countArg = argList.namedChildren[0];
                            const sizeArg = argList.namedChildren[1];
                            
                            if (countArg && sizeArg && 
                                countArg.type === 'number_literal' && 
                                sizeArg.type === 'number_literal') {
                                const count = parseInt(countArg.text, 10);
                                const size = parseInt(sizeArg.text, 10);
                                const total = count * size;
                                
                                if (total > memoryThreshold) {
                                    issues.push(
                                        `Warning: Excessive memory allocation (${total} bytes) using "${fnName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                                    );
                                }
                            }
                        }
                    }
                }
            }
            
            // Continue traversing the AST for non-loop nodes
            node.namedChildren.forEach(child => traverse(child, inheritedModifiedVars));
        }
        
        // Start traversal from the root
        traverse(tree.rootNode);
        
        // Final step: Filter out false positives if not in strict mode
        if (detectionLevel === 'relaxed') {
            // Only keep the most serious warnings
            return issues.filter(issue => 
                issue.includes('always-true condition') || 
                issue.includes('never modified')
            );
        }
        
        return issues;
    }
}