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

export class RaceConditionCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Get configuration for race detection sensitivity
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const detectionLevel = config.get<string>('fileRaceDetectionLevel', 'moderate');
        
        // Advanced tracking of file operations and context
        const context = {
            fileOperations: new Map<string, {node: Parser.SyntaxNode, operation: string, path?: string}>(), // filepath -> operation info
            lockOperations: new Map<string, {node: Parser.SyntaxNode, lockType: string}>(), // filepath -> lock info
            fileDescriptors: new Map<string, string>(), // fd variable -> filepath
            // Track if we're in a synchronized context
            synchronizedContext: false,
            // Track paired operations that could lead to TOCTOU
            checkOperations: new Map<string, Parser.SyntaxNode>(), // filepath -> check node
            useOperations: new Map<string, Parser.SyntaxNode>(), // filepath -> use node
            hasPotentialRaceCondition: false
        };
        
        // Track filenames and their variables
        const filePathVariables = new Set<string>();
        const fileDescriptorVariables = new Set<string>();
        
        // Enhanced keywords for race condition detection
        const fileAccessFunctions = config.get<string[]>('raceConditionKeywords', [
            // Standard C file operations
            'fopen', 'freopen', 'fwrite', 'fread', 'fprintf', 'fputs', 'fscanf',
            'fgets', 'fgetc', 'ftell', 'fseek', 'rewind', 
            // POSIX file operations
            'open', 'read', 'write', 'pread', 'pwrite',
            // C++ file operations
            'ifstream', 'ofstream', 'fstream'
        ]);

        // Expanded list of metadata operations that can lead to TOCTOU
        const metadataFunctions = [
            'access', 'stat', 'lstat', 'fstat', 'chmod', 'chown',
            'mkdir', 'rmdir', 'unlink', 'remove', 'rename', 'link', 'symlink',
            'readlink', 'realpath', 'opendir', 'readdir', 'closedir'
        ];
        
        // Expanded list of locking mechanisms
        const fileLockFunctions = [
            'flock', 'lockf', 'fcntl', 'pthread_mutex_lock', 'pthread_mutex_trylock',
            'pthread_rwlock_rdlock', 'pthread_rwlock_wrlock', 'sem_wait',
            'flockfile', 'ftrylockfile', 'funlockfile', 'mtx_lock', 'mtx_timedlock'
        ];
        
        // Functions that release locks
        const unlockFunctions = [
            'pthread_mutex_unlock', 'pthread_rwlock_unlock', 'sem_post',
            'funlockfile', 'mtx_unlock'
        ];
        
        // Functions that might indicate a boundary where race conditions are less likely
        const boundaryFunctions = [
            'exit', 'abort', 'return', 'pthread_exit', 'longjmp', '_Exit'
        ];
        
        // Atomic operations or functions that prevent races
        const atomicOperations = [
            'atomic_', 'std::atomic', '__sync_', '__atomic_'
        ];

        // Format line number information for warnings
        function formatLineInfo(node: Parser.SyntaxNode): string {
            return `line ${node.startPosition.row + 1}`;
        }
        
        // Helper: Check if a path argument is a string literal or a variable
        function extractPathArgument(argNode: Parser.SyntaxNode): string | undefined {
            if (!argNode) return undefined;
            
            if (argNode.type === 'string_literal') {
                // Remove quotes from string literals
                return argNode.text.replace(/^["'](.*)["']$/, '$1');
            } else if (argNode.type === 'identifier') {
                // Track variable names that might contain paths
                filePathVariables.add(argNode.text);
                return argNode.text;
            }
            
            return undefined;
        }
        
        // Helper: Check if we have an operation on a file that might cause races
        function trackFileOperation(node: Parser.SyntaxNode, fnName: string, pathArg?: Parser.SyntaxNode): void {
            // Extract the path argument if provided
            const path = pathArg ? extractPathArgument(pathArg) : undefined;
            
            if (path) {
                context.fileOperations.set(path, {
                    node,
                    operation: fnName,
                    path
                });
                
                // Check if this is a 'check' operation like access() or stat()
                if (metadataFunctions.includes(fnName)) {
                    context.checkOperations.set(path, node);
                }
                
                // Check if this is a 'use' operation like open() or fopen()
                if (fileAccessFunctions.includes(fnName)) {
                    context.useOperations.set(path, node);
                    
                    // If we also have a 'check' operation on this path, it's a potential TOCTOU
                    if (context.checkOperations.has(path)) {
                        context.hasPotentialRaceCondition = true;
                        
                        // Only add TOCTOU warnings in moderate or strict mode
                        if (detectionLevel !== 'relaxed') {
                            // Get the check operation node
                            const checkNode = context.checkOperations.get(path)!;
                            
                            issues.push(
                                `Warning: TOCTOU vulnerability detected - "${fnName}" on path "${path}" at ${formatLineInfo(node)} follows a check at ${formatLineInfo(checkNode)}. Consider atomic operations.`
                            );
                        }
                    }
                }
            }
        }
        
        // Helper: Determine if an operation might be protected by synchronization
        function isLikelyProtected(operation: string, path: string): boolean {
            // Check if we have a lock operation for this path
            return context.lockOperations.has(path) || context.synchronizedContext;
        }
        
        // Helper: Check if a function name indicates a synchronization operation
        function isSynchronizationFunction(fnName: string): boolean {
            return fileLockFunctions.some(lockFn => fnName.toLowerCase().includes(lockFn.toLowerCase()));
        }
        
        // Helper: Check if a function name indicates an atomic operation
        function isAtomicOperation(fnName: string): boolean {
            return atomicOperations.some(atomicFn => fnName.toLowerCase().includes(atomicFn.toLowerCase()));
        }
        
        // Helper: Identify safe file operation patterns
        function isSafeFileOperationPattern(operations: Map<string, {node: Parser.SyntaxNode, operation: string, path?: string}>): boolean {
            // Check if we have a simple open-use-close pattern within the same function scope
            
            if (operations.size < 2) {
                return false; // Not enough operations to form a pattern
            }
            
            // Group operations by file path
            const pathOperations: Map<string, {operation: string, index: number}[]> = new Map();
            
            // Sort operations by node position to determine sequence
            const sortedOperations = Array.from(operations.values())
                .filter(op => op.path) // Only consider operations with known paths
                .sort((a, b) => a.node.startIndex - b.node.startIndex);
            
            // Group by path
            for (let i = 0; i < sortedOperations.length; i++) {
                const op = sortedOperations[i];
                if (!op.path) continue;
                
                if (!pathOperations.has(op.path)) {
                    pathOperations.set(op.path, []);
                }
                
                pathOperations.get(op.path)!.push({
                    operation: op.operation,
                    index: i
                });
            }
            
            // Check each path's operation sequence
            for (const [path, ops] of pathOperations.entries()) {
                if (ops.length < 2) continue; // Need at least 2 operations
                
                // Check for classic patterns:
                // 1. Open-Close pattern (potentially with operations in between)
                const hasOpen = ops.some(op => ['fopen', 'open'].includes(op.operation));
                const hasClose = ops.some(op => ['fclose', 'close'].includes(op.operation));
                
                // Find first open and last close
                const firstOpen = ops.find(op => ['fopen', 'open'].includes(op.operation));
                const lastClose = [...ops].reverse().find(op => ['fclose', 'close'].includes(op.operation));
                
                if (hasOpen && hasClose && firstOpen && lastClose) {
                    const allOpsInSequence = ops.every(op => 
                        op.index >= firstOpen.index && op.index <= lastClose.index
                    );
                    
                    if (allOpsInSequence) {
                        // All operations on this file are between open and close
                        // This is likely a safe pattern
                        return true;
                    }
                }
            }
            
            return false;
        }

        initParser();
        const tree = parser.parse(methodBody);

        // First pass: identify file descriptor variables
        function identifyFileDescriptors(node: Parser.SyntaxNode) {
            // Look for file descriptor assignments from open/fopen calls
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0);
                const rhs = node.child(2);
                
                if (lhs?.type === 'identifier' && rhs?.type === 'call_expression') {
                    const fnName = rhs.child(0)?.text;
                    
                    if (fnName === 'fopen' || fnName === 'open') {
                        const fdVar = lhs.text;
                        fileDescriptorVariables.add(fdVar);
                        
                        // If we can extract the path, associate it with this file descriptor
                        const argList = rhs.child(1);
                        if (argList && argList.namedChildren.length > 0) {
                            const pathArg = argList.namedChildren[0];
                            const path = extractPathArgument(pathArg);
                            
                            if (path) {
                                context.fileDescriptors.set(fdVar, path);
                            }
                        }
                    }
                }
            }
            
            node.namedChildren.forEach(identifyFileDescriptors);
        }

        // Perform first pass to identify file descriptors
        identifyFileDescriptors(tree.rootNode);
        
        // Main analysis pass
        function traverse(node: Parser.SyntaxNode) {
            // Look for critical sections or synchronized contexts
            if (node.type === 'block' || node.type === 'compound_statement') {
                // Check if this block is preceded by a lock operation
                const prevSibling = node.previousSibling;
                if (prevSibling?.type === 'call_expression') {
                    const fnName = prevSibling.child(0)?.text || '';
                    
                    if (fileLockFunctions.some(lockFn => fnName.toLowerCase().includes(lockFn.toLowerCase()))) {
                        // This block is likely protected by a lock
                        const prevSynchronizedContext = context.synchronizedContext;
                        context.synchronizedContext = true;
                        
                        // Recursively process the synchronized block
                        node.namedChildren.forEach(traverse);
                        
                        // Restore previous context
                        context.synchronizedContext = prevSynchronizedContext;
                        
                        // Skip further processing of this node since we already traversed it
                        return;
                    }
                }
            }
            
            // Check for function calls that might indicate file operations
            if (node.type === 'call_expression') {
                const fnNode = node.child(0);
                const fnName = fnNode?.text || '';
                const argList = node.child(1);
                
                // Track operations that might involve files
                if (fileAccessFunctions.includes(fnName)) {
                    // Extract the path argument (typically the first argument)
                    const pathArg = argList?.namedChildren[0];
                    trackFileOperation(node, fnName, pathArg);
                    
                    // Only warn if not in a synchronized context and not properly locked
                    if (!context.synchronizedContext) {
                        const pathStr = pathArg ? extractPathArgument(pathArg) : 'unknown';
                        const isProtected = pathStr ? isLikelyProtected(fnName, pathStr) : false;
                        

                                                // 🚫 Skip harmless cleanup like fclose
                        if (['fclose', 'close'].includes(fnName)) {
                            return;
                        }

                        // ✅ Suppress benign writes if part of a safe fopen–write–fclose pattern
                        if (
                            ['fprintf', 'fputs', 'fwrite'].includes(fnName) &&
                            isSafeFileOperationPattern(context.fileOperations)
                        ) {
                            return;
                        }

                        // Check if this operation is part of a safe pattern
                        const isPartOfSafePattern = isSafeFileOperationPattern(context.fileOperations);
                        
                        // Only warn based on detection level and safety analysis
                        if (!isProtected && 
                            (detectionLevel === 'strict' || 
                             (detectionLevel === 'moderate' && !isPartOfSafePattern))) {
                            issues.push(
                                `Warning: Unprotected file operation "${fnName}" detected at ${formatLineInfo(node)} in method "${methodName}". Consider using proper file locking.`
                            );
                        }
                    }
                }
                
                // Track metadata operations
                if (metadataFunctions.includes(fnName)) {
                    // Extract the path argument (typically the first argument)
                    const pathArg = argList?.namedChildren[0];
                    trackFileOperation(node, fnName, pathArg);
                    
                    // Warn about potential TOCTOU vulnerabilities
                    if (!context.synchronizedContext && detectionLevel !== 'relaxed') {
                        issues.push(
                            `Warning: File metadata operation "${fnName}" at ${formatLineInfo(node)} in method "${methodName}" may lead to TOCTOU vulnerabilities.`
                        );
                    }
                }
                
                // Track lock operations
                if (fileLockFunctions.some(lockFn => fnName.toLowerCase().includes(lockFn.toLowerCase()))) {
                    // If this is a file-specific lock like flock
                    if (fnName === 'flock' || fnName === 'lockf') {
                        const fdArg = argList?.namedChildren[0];
                        
                        if (fdArg?.type === 'identifier') {
                            const fdVar = fdArg.text;
                            
                            // If we know which file this descriptor refers to
                            if (context.fileDescriptors.has(fdVar)) {
                                const path = context.fileDescriptors.get(fdVar)!;
                                context.lockOperations.set(path, {
                                    node,
                                    lockType: fnName
                                });
                            }
                        }
                    } else {
                        // General synchronization primitives
                        context.synchronizedContext = true;
                    }
                }
                
                // Track unlock operations
                if (unlockFunctions.some(unlockFn => fnName.toLowerCase().includes(unlockFn.toLowerCase()))) {
                    // End synchronized context if this is a general unlock
                    context.synchronizedContext = false;
                }
                
                // Check for operations on file descriptor variables
                if (argList) {
                    for (const arg of argList.namedChildren) {
                        if (arg.type === 'identifier' && fileDescriptorVariables.has(arg.text)) {
                            // This is an operation on a file descriptor
                            const fdVar = arg.text;
                            const path = context.fileDescriptors.get(fdVar);
                            
                            if (path && !isLikelyProtected(fnName, path) && !context.synchronizedContext) {
                                // Check if this is part of a safe pattern before warning
                                const isPartOfSafePattern = isSafeFileOperationPattern(context.fileOperations);
                                
                                if (detectionLevel === 'strict' || 
                                    (detectionLevel === 'moderate' && !isPartOfSafePattern)) {
                                    issues.push(
                                        `Warning: Unprotected operation "${fnName}" on file descriptor "${fdVar}" at ${formatLineInfo(node)} in method "${methodName}".`
                                    );
                                }
                            }
                        }
                    }
                }
                
                // Check for atomic operations that might prevent races
                if (isAtomicOperation(fnName)) {
                    // This is likely safe from race conditions, no warning needed
                }
            }
            
            // Continue traversing the AST
            node.namedChildren.forEach(traverse);
        }

        // Execute the main analysis
        traverse(tree.rootNode);
        
        // Final analysis to detect missing locks - with enhanced pattern detection
        if (context.fileOperations.size > 0 && context.lockOperations.size === 0 && !context.synchronizedContext) {
            // Check if the operations follow a safe pattern
            const isPartOfSafePattern = isSafeFileOperationPattern(context.fileOperations);
            
            // Only add general warning if needed based on detection level and safe pattern analysis
            if ((detectionLevel === 'strict' || 
                (detectionLevel === 'moderate' && !isPartOfSafePattern)) && 
                !issues.some(msg => msg.includes('Unprotected'))) {
                
                issues.push(
                    `Warning: File operations detected without proper synchronization in method "${methodName}". Consider using locking functions like flock(), pthread_mutex_lock(), or other synchronization mechanisms.`
                );
            }
        }
        
        // Check for TOCTOU patterns across the entire method
        for (const [path, checkNode] of context.checkOperations) {
            // If we have both check and use operations on the same path, it's a potential TOCTOU
            const useNode = context.useOperations.get(path);
            
            if (useNode && checkNode.startIndex < useNode.startIndex) {
                // Only add if we haven't already warned about this specific instance
                // and if the detection level is appropriate
                if (detectionLevel !== 'relaxed' &&
                    !issues.some(msg => msg.includes(`TOCTOU vulnerability detected`) && msg.includes(path))) {
                    issues.push(
                        `Warning: Potential TOCTOU vulnerability on path "${path}" - checked at ${formatLineInfo(checkNode)} and used at ${formatLineInfo(useNode)} in method "${methodName}".`
                    );
                }
            }
        }

        return issues;
    }
}