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

export class FloatingInMemoryCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Data structures for tracking variables
        const heapAllocations = new Map<string, {
            allocator: string,
            line: number,
            freed: boolean,
            size: string | null,
            scope: number
        }>();
        const freeOperations = new Map<string, number>(); // variable -> line number
        const variableUses = new Map<string, number[]>(); // variable -> line numbers
        const aliases = new Map<string, string>(); // alias -> original
        const nullAssignments = new Map<string, number[]>(); // variable -> line numbers
        const returns = new Set<number>(); // line numbers of return statements
        const doubleFreePotential = new Set<string>(); // variables with potential double free
        const currentScope = { level: 0 };
        
        // NEW: Track functions that return heap-allocated memory
        const heapReturningFunctions = new Set<string>();
        
        // Get configuration values
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const heapAllocators = config.get<string[]>('heapAllocators', [
            'malloc', 'calloc', 'realloc', 'aligned_alloc', 'memalign', 'strdup'
        ]);
        const freeOperators = config.get<string[]>('freeOperators', [
            'free', 'cfree', 'delete', 'delete[]'
        ]);
        const accessOperations = config.get<string[]>('accessOperations', [
            'memcpy', 'strcpy', 'strcat', 'sprintf', 'read', 'write'
        ]);
        
        // NEW: Keywords that suggest a function is returning heap memory
        const heapFunctionIndicators = [
            'alloc', 'create', 'new', 'dup', 'copy', 'clone', 'strdup', 'strndup'
        ];
        
        initParser();
        const tree = parser.parse(methodBody);
        
        // Helper function to get line number
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }
        
        // Helper to track variable usage
        function trackVariableUse(variable: string, line: number) {
            if (!variable) return;
            
            // Resolve aliases to track the original variable
            const original = aliases.get(variable) || variable;
            
            // Add to usage tracking
            if (variableUses.has(original)) {
                variableUses.get(original)?.push(line);
            } else {
                variableUses.set(original, [line]);
            }
        }
        
        // NEW: Helper to check if a function likely returns heap memory
        function isLikelyHeapReturningFunction(functionName: string): boolean {
            // Known heap-returning functions
            if (heapReturningFunctions.has(functionName)) {
                return true;
            }
            
            // Check for function name patterns that suggest heap allocation
            for (const indicator of heapFunctionIndicators) {
                if (functionName.toLowerCase().includes(indicator)) {
                    return true;
                }
            }
            
            // Common function names that return heap memory
            return functionName.includes('read_line') || 
                   functionName.includes('getline') ||
                   functionName.includes('makeString') ||
                   functionName.includes('createBuffer');
        }
        
        // NEW: First pass - identify functions that return heap-allocated memory
        function identifyHeapReturningFunctions(node: Parser.SyntaxNode) {
            if (node.type === 'function_definition') {
                const name = node.childForFieldName('declarator')?.descendantsOfType('identifier')?.[0]?.text;
                
                if (name) {
                    // Look for return statements that return heap-allocated memory
                    const returnNodes = node.descendantsOfType('return_statement');
                    let returnsHeapMemory = false;
                    
                    for (const returnNode of returnNodes) {
                        const returnExpr = returnNode.child(1);
                        
                        // Check if returning a variable that might be heap-allocated
                        if (returnExpr?.type === 'identifier' && heapAllocations.has(returnExpr.text)) {
                            returnsHeapMemory = true;
                            break;
                        }
                        
                        // Check if returning the result of a heap allocation function directly
                        if (returnExpr?.type === 'call_expression') {
                            const fnName = returnExpr.child(0)?.text;
                            if (heapAllocators.includes(fnName || '')) {
                                returnsHeapMemory = true;
                                break;
                            }
                        }
                    }
                    
                    // Also check if function name suggests heap allocation
                    if (returnsHeapMemory || isLikelyHeapReturningFunction(name)) {
                        heapReturningFunctions.add(name);
                    }
                }
            }
            
            // Recursively check all nodes
            for (const child of node.namedChildren) {
                identifyHeapReturningFunctions(child);
            }
        }
        
        // Main AST traversal function
        function traverse(node: Parser.SyntaxNode) {
            // Track scope for analysis
            if (node.type === 'compound_statement') {
                currentScope.level++;
                
                // Process children with updated scope
                node.namedChildren.forEach(child => traverse(child));
                
                // Return to previous scope
                currentScope.level--;
                return;
            }
            
            // Track return statements
            if (node.type === 'return_statement') {
                returns.add(getLineNumber(node));
            }
            
            // Track if statement conditions - might be null checks
            if (node.type === 'if_statement') {
                const condition = node.childForFieldName('condition');
                const identifiers = condition?.descendantsOfType('identifier') || [];
                
                // Track identifiers used in conditions
                identifiers.forEach(id => {
                    const varName = id.text;
                    trackVariableUse(varName, getLineNumber(node));
                });
            }
            
            // Track NULL assignments
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const right = node.child(2);
                
                if (left?.type === 'identifier' && right) {
                    const varName = left.text;
                    const line = getLineNumber(node);
                    
                    // Track aliasing (ptr = another_ptr)
                    if (right.type === 'identifier') {
                        const rightVar = right.text;
                        
                        // If right side is a heap allocation, the left side becomes its alias
                        if (heapAllocations.has(rightVar)) {
                            aliases.set(varName, rightVar);
                            // Also track this use of the original pointer
                            trackVariableUse(rightVar, line);
                        }
                    }
                    
                    // Track NULL assignments (ptr = NULL)
                    if (right.type === 'null') {
                        if (nullAssignments.has(varName)) {
                            nullAssignments.get(varName)?.push(line);
                        } else {
                            nullAssignments.set(varName, [line]);
                        }
                        
                        // If this variable had been allocated, it's no longer valid
                        if (heapAllocations.has(varName) && heapAllocations.get(varName)?.freed) {
                            // Setting a freed pointer to NULL is actually good practice
                            // So we don't issue a warning here
                        }
                    }
                    
                    // NEW: Track function calls that return heap-allocated memory
                    if (right.type === 'call_expression') {
                        const fnName = right.child(0)?.text || '';
                        const args = right.child(1)?.namedChildren || [];
                        
                        // Check if it's a heap allocation function
                        if (heapAllocators.includes(fnName)) {
                            // Extract size expression if possible
                            let sizeExpr = null;
                            if (fnName === 'malloc' && args.length >= 1) {
                                sizeExpr = args[0].text;
                            } else if (fnName === 'calloc' && args.length >= 2) {
                                sizeExpr = `${args[0].text} * ${args[1].text}`;
                            } else if (fnName === 'realloc' && args.length >= 2) {
                                sizeExpr = args[1].text;
                                
                                // For realloc, also track use of the first argument
                                if (args[0].type === 'identifier') {
                                    trackVariableUse(args[0].text, line);
                                }
                            }
                            
                            // Record this heap allocation
                            heapAllocations.set(varName, {
                                allocator: fnName,
                                line,
                                freed: false,
                                size: sizeExpr,
                                scope: currentScope.level
                            });
                        }
                        // Check if it's a function that returns heap-allocated memory
                        else if (isLikelyHeapReturningFunction(fnName) || heapReturningFunctions.has(fnName)) {
                            // Record this as a heap allocation
                            heapAllocations.set(varName, {
                                allocator: 'function_return',
                                line,
                                freed: false,
                                size: null,
                                scope: currentScope.level
                            });
                        }
                    }
                }
            }
            
            // Track declaration with initialization
            if (node.type === 'declaration') {
                for (const child of node.namedChildren) {
                    if (child.type === 'init_declarator') {
                        const pointerDecl = child.childForFieldName('declarator');
                        const value = child.childForFieldName('value');
                        let identifierNode: Parser.SyntaxNode | null = null;
            
                        if (pointerDecl?.type === 'pointer_declarator') {
                            identifierNode = pointerDecl.namedChild(0);
                        } else if (pointerDecl?.type === 'identifier') {
                            identifierNode = pointerDecl;
                        }
            
                        if (identifierNode?.type === 'identifier' && value?.type === 'call_expression') {
                            const varName = identifierNode.text;
                            const fnName = value.child(0)?.text || '';
                            const args = value.child(1)?.namedChildren || [];
                            const line = getLineNumber(child);
            
                            // Check if it's a heap allocation function
                            if (heapAllocators.includes(fnName)) {
                                let sizeExpr = null;
                                if (fnName === 'malloc' && args.length >= 1) {
                                    sizeExpr = args[0].text;
                                } else if (fnName === 'calloc' && args.length >= 2) {
                                    sizeExpr = `${args[0].text} * ${args[1].text}`;
                                }
            
                                heapAllocations.set(varName, {
                                    allocator: fnName,
                                    line,
                                    freed: false,
                                    size: sizeExpr,
                                    scope: currentScope.level
                                });
                            }
                            // NEW: Check if it's a function that returns heap-allocated memory
                            else if (isLikelyHeapReturningFunction(fnName) || heapReturningFunctions.has(fnName)) {
                                heapAllocations.set(varName, {
                                    allocator: 'function_return',
                                    line,
                                    freed: false,
                                    size: null,
                                    scope: currentScope.level
                                });
                            }
                        }
                    }
                }
            }
            
            // Track free operations
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const args = node.child(1)?.namedChildren || [];
                const line = getLineNumber(node);
                
                // Check if it's a memory free function
                if (freeOperators.includes(fnName) && args.length > 0) {
                    const arg = args[0];
                    
                    if (arg.type === 'identifier') {
                        const varName = arg.text;
                        const originalVar = aliases.get(varName) || varName;
                        
                        // Record this free operation
                        freeOperations.set(originalVar, line);
                        
                        // Mark the variable as freed
                        if (heapAllocations.has(originalVar)) {
                            // If already freed, this is a double-free
                            if (heapAllocations.get(originalVar)?.freed) {
                                issues.push(
                                    `Warning: Double-free vulnerability detected for variable "${varName}" at line ${line} in method "${methodName}". Variable was already freed at line ${freeOperations.get(originalVar)}.`
                                );
                                doubleFreePotential.add(originalVar);
                            } else {
                                // Update allocation record to mark as freed
                                const alloc = heapAllocations.get(originalVar);
                                if (alloc) {
                                    alloc.freed = true;
                                    heapAllocations.set(originalVar, alloc);
                                }
                            }
                        } else {
                            // Freeing a non-allocated pointer or something we don't track
                            const isAliased = Array.from(aliases.values()).includes(originalVar);
                            if (!isAliased) {
                                // NEW: Only warn if this isn't in a false positive pattern
                                // Don't warn if this is a parameter that's being freed
                                const isParameter = false; // TODO: Implement parameter detection
                                
                                // Don't warn if this might be from a function that returns heap memory
                                // but we missed detecting it
                                const possiblyFromHeapFunction = !isParameter && /read|get|create|make|alloc/.test(methodBody);
                                
                                if (!possiblyFromHeapFunction) {
                                    issues.push(
                                        `Warning: Freeing non-allocated or invalid pointer "${varName}" at line ${line} in method "${methodName}".`
                                    );
                                }
                            }
                        }
                    }
                }

                // Track memory access operations that could cause use-after-free
                if (accessOperations.includes(fnName)) {
                    // Check if any arguments are heap-allocated variables
                    args.forEach(arg => {
                        if (arg.type === 'identifier') {
                            const varName = arg.text;
                            const originalVar = aliases.get(varName) || varName;
                            
                            // Track this use
                            trackVariableUse(originalVar, line);
                        }
                    });
                }
            }
            
            // Track all other uses of identifiers (could be use-after-free)
            if (node.type === 'identifier') {
                // Skip identifiers that are just function names
                if (node.parent?.type === 'call_expression' && node.parent.child(0) === node) {
                    // This is a function name, not a variable use
                } else {
                    trackVariableUse(node.text, getLineNumber(node));
                }
            }
            
            // Check subscript expressions (array access) - common source of use-after-free
            if (node.type === 'subscript_expression') {
                const array = node.child(0);
                if (array?.type === 'identifier') {
                    const varName = array.text;
                    const line = getLineNumber(node);
                    trackVariableUse(varName, line);
                }
            }
            
            // Check unary expressions like *ptr (dereferencing) - common source of use-after-free
            if (node.type === 'unary_expression' && node.text.startsWith('*')) {
                const operand = node.child(0);
                if (operand?.type === 'identifier') {
                    const varName = operand.text;
                    const line = getLineNumber(node);
                    trackVariableUse(varName, line);
                }
            }
            
            // Check struct field accesses like ptr->field or ptr.field
            if (node.type === 'field_expression') {
                const object = node.child(0);
                if (object?.type === 'identifier') {
                    const varName = object.text;
                    const line = getLineNumber(node);
                    trackVariableUse(varName, line);
                }
            }
            
            // Process children
            node.namedChildren.forEach(child => traverse(child));
        }
        
        // FIRST: Perform a quick analysis to find functions that return heap memory
        identifyHeapReturningFunctions(tree.rootNode);
        
        // SECOND: Perform the main analysis to find memory errors
        traverse(tree.rootNode);
        
        // Post-processing to detect issues
        
        // 1. Detect memory leaks (allocated but not freed)
        heapAllocations.forEach((details, varName) => {
            if (!details.freed) {
                // Check if this variable is returned (which might not be a leak)
                const uses = variableUses.get(varName) || [];
                const isReturned = returns.size > 0 && uses.some(line => 
                    returns.has(line) || returns.has(line - 1) || returns.has(line + 1)
                );
                
                if (isReturned) {
                    // If returned, it might be intentional - responsibility transfers to caller
                    issues.push(
                        `Info: Heap-allocated variable "${varName}" at line ${details.line} is returned from method "${methodName}" without being freed. Ensure it's freed by the caller.`
                    );
                } else {
                    // Not returned - likely a memory leak
                    issues.push(
                        `Warning: Memory leak detected: Variable "${varName}" allocated at line ${details.line} in method "${methodName}" is never freed.`
                    );
                }
            }
        });
        
        // 2. Detect use-after-free
        freeOperations.forEach((freeLine, varName) => {
            const uses = variableUses.get(varName) || [];
            
            // Look for uses after the free
            const usesAfterFree = uses.filter(line => line > freeLine);
            
            // Skip if the variable is in doubleFreePotential (already warned)
            if (usesAfterFree.length > 0 && !doubleFreePotential.has(varName)) {
                // Check if it's nullified after freeing
                const nullifications = nullAssignments.get(varName) || [];
                const nullAfterFree = nullifications.some(line => line > freeLine && line < Math.min(...usesAfterFree));
                
                if (!nullAfterFree) {
                    issues.push(
                        `Warning: Use-after-free vulnerability detected: Variable "${varName}" is used at line ${usesAfterFree[0]} after being freed at line ${freeLine} in method "${methodName}".`
                    );
                    
                    // Add more specific details if there are multiple uses after free
                    if (usesAfterFree.length > 1) {
                        issues.push(
                            `Info: Additional use-after-free occurrences for "${varName}" at lines: ${usesAfterFree.slice(1).join(', ')} in method "${methodName}".`
                        );
                    }
                }
            }
        });
        
        return issues;
    }
}