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
        
        // Context tracking for better analysis
        const context = {
            loopContexts: new Map<string, {
                node: Parser.SyntaxNode,
                variables: Set<string>,
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
        
        // Enhanced helper functions
        
        // Generate unique node ID
        function nodeKey(node: Parser.SyntaxNode): string {
            return `${node.type}-${node.startPosition.row}:${node.startPosition.column}`;
        }
        
        // Add line number info to warnings
        function formatLineInfo(node: Parser.SyntaxNode): string {
            return `line ${node.startPosition.row + 1}`;
        }
        
        // Extract all variables from a condition expression
        function extractVariablesFromCondition(conditionNode: Parser.SyntaxNode | null): Set<string> {
            const variables = new Set<string>();
            
            if (!conditionNode) return variables;
            
            function collectIdentifiers(node: Parser.SyntaxNode) {
                if (node.type === 'identifier') {
                    variables.add(node.text);
                }
                
                node.children.forEach(collectIdentifiers);
            }
            
            collectIdentifiers(conditionNode);
            return variables;
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
        
        // Track variables modified in a block
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
        
        // Detect if a condition is always true or has no exit condition
        function isAlwaysTrueCondition(conditionNode: Parser.SyntaxNode | null): boolean {
            if (!conditionNode) return true; // No condition means infinite
            
            const conditionText = conditionNode.text.trim();
            
            // Direct constants
            if (conditionText === '1' || 
                conditionText.toLowerCase() === 'true' || 
                conditionText === '!0') {
                return true;
            }
            
            // Check for expressions that are always true
            if (conditionNode.type === 'binary_expression') {
                const operator = conditionNode.child(1)?.text;
                const lhs = conditionNode.child(0);
                const rhs = conditionNode.child(2);
                
                // Check for expressions like (1 == 1) or (2 > 1)
                if (lhs?.type === 'number_literal' && rhs?.type === 'number_literal') {
                    if (operator === '==' && lhs.text === rhs.text) {
                        return true;
                    }
                    
                    // Other tautologies like (1 <= 2)
                    if (operator === '<=' || operator === '>=') {
                        const lhsValue = parseInt(lhs.text, 10);
                        const rhsValue = parseInt(rhs.text, 10);
                        
                        if ((operator === '<=' && lhsValue <= rhsValue) ||
                            (operator === '>=' && lhsValue >= rhsValue)) {
                            return true;
                        }
                    }
                }
            }
            
            return false;
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
            const conditionVars = extractVariablesFromCondition(conditionNode);
            
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
            
            // Check for excessive memory allocations
            const hasExcessiveMemory = bodyNode ? hasExcessiveMemoryUsage(bodyNode) : false;
            
            // Store context for this loop
            context.loopContexts.set(key, {
                node,
                variables: conditionVars,
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
            
            // 2. Check for condition variables that aren't modified
            else {
                const unmodifiedVars = Array.from(conditionVars)
                    .filter(varName => !totalModifiedVars.has(varName));
                
                if (unmodifiedVars.length > 0 && 
                    !terminationInfo.hasBreak && 
                    !terminationInfo.hasReturn && 
                    !terminationInfo.hasExit &&
                    !terminationInfo.hasThrow &&
                    !isWaitLoop) {
                    issues.push(
                        `Warning: Loop condition variable(s) [${unmodifiedVars.join(', ')}] never modified in method "${methodName}" at ${formatLineInfo(node)}. This may result in an infinite loop.`
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