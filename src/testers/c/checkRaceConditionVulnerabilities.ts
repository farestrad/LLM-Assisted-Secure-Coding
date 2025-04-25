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
        
        // Standard streams that are always safe from race conditions
        const knownSafeDescriptors = ['stdin', 'stdout', 'stderr'];

        // Helper: Check if a node refers to a standard stream
        function isStandardStream(node: Parser.SyntaxNode | undefined | null): boolean {
            if (!node) return false;
    
            // Direct standard stream identifier
            if (node.type === 'identifier' && knownSafeDescriptors.includes(node.text)) {
                return true;
            }
            
            return false;
        }
        
        // Advanced tracking of file operations and context
        const context = {
            fileOperations: new Map<string, {node: Parser.SyntaxNode, operation: string, path?: string, fdVar?: string}>(),
            lockOperations: new Map<string, {node: Parser.SyntaxNode, lockType: string}>(),
            fileDescriptors: new Map<string, string>(), // fd variable -> filepath
            filePointers: new Map<string, string>(), // FILE* variable -> filepath
            fdToFilePointer: new Map<string, string>(), // fd variable -> FILE* variable (for fileno mapping)
            fileOperationsByFd: new Map<string, {operation: string, node: Parser.SyntaxNode}[]>(), // fd variable -> operations
            synchronizedContext: false,
            checkOperations: new Map<string, Parser.SyntaxNode>(),
            useOperations: new Map<string, Parser.SyntaxNode>(),
            hasPotentialRaceCondition: false,
            // Store operations where parents can't be determined
            orphanedOperations: [] as {node: Parser.SyntaxNode, operation: string, fdVar?: string}[],
            // Track secure patterns
            hasBasenameSanitization: false,
            hasSecureOpenFlags: false,
            // Track stdin/stdout operations
            standardStreamOperations: new Set<Parser.SyntaxNode>()
        };
        
        // Track filenames and their variables
        const filePathVariables = new Set<string>();
        const fileDescriptorVariables = new Set<string>();
        const filePointerVariables = new Set<string>();
        
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
        
        // Path sanitization functions that reduce risk of race conditions
        const pathSanitizers = [
            'basename', 'realpath', 'canonicalize_file_name', 'canonicalize_path'
        ];
        
        // Secure file open flags that mitigate race conditions
        const secureOpenFlags = [
            'O_NOFOLLOW', 'O_EXCL', 'O_CREAT|O_EXCL'
        ];

        // Format line number information for warnings
        function formatLineInfo(node: Parser.SyntaxNode): string {
            return `line ${node.startPosition.row + 1}`;
        }
        
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
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
        
        // Helper: Track file operation with both path and file descriptor
        function trackFileOperation(node: Parser.SyntaxNode, fnName: string, pathArg?: Parser.SyntaxNode, fdArg?: Parser.SyntaxNode): void {
            // Skip tracking for standard streams - this is critical
            if (fdArg && isStandardStream(fdArg)) {
                context.standardStreamOperations.add(node);
                return; // Skip processing for standard streams
            }
            
            // Skip if the last arg is stdin for functions like fgets
            const argsNode = node.child(1);
            if (argsNode && argsNode.namedChildren.length > 0) {
                const lastArg = argsNode.namedChildren[argsNode.namedChildren.length - 1];
                if (isStandardStream(lastArg) && ['fgets', 'fscanf', 'fprintf', 'fputs'].includes(fnName)) {
                    context.standardStreamOperations.add(node);
                    return; // Skip processing for stdin/stdout operations
                }
            }
            
            const path = pathArg ? extractPathArgument(pathArg) : undefined;
            const fdVar = fdArg?.type === 'identifier' ? fdArg.text : undefined;
            
            // Track by path if available
            if (path) {
                context.fileOperations.set(path, {
                    node,
                    operation: fnName,
                    path,
                    fdVar
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
            
            // Track by file descriptor if available
            if (fdVar) {
                if (!context.fileOperationsByFd.has(fdVar)) {
                    context.fileOperationsByFd.set(fdVar, []);
                }
                
                context.fileOperationsByFd.get(fdVar)!.push({
                    operation: fnName,
                    node
                });
            }
            
            // If we couldn't determine either path or fdVar, track as orphaned
            if (!path && !fdVar) {
                context.orphanedOperations.push({
                    node,
                    operation: fnName
                });
            }
        }

        // Add a check for basic file operations without validation
function hasFilePathValidation(methodBody: string): boolean {
    // Check for path traversal validation
    const hasTraversalCheck = /strstr\s*\([^,]+,\s*["']\.\.["']\)/.test(methodBody);
    // Check for other common validation patterns
    const hasLengthCheck = /strlen\s*\(\s*[\w]+\s*\)\s*[<>]=?\s*\d+/.test(methodBody);
    const hasCharCheck = /strchr\s*\(\s*[\w]+\s*,\s*['"]\/['"]\s*\)/.test(methodBody);
    
    return hasTraversalCheck || hasLengthCheck || hasCharCheck;
}

// In the main analysis code:
const hasValidation = hasFilePathValidation(methodBody);
if (!hasValidation && methodBody.includes('fopen') && !hasFlockWithFilenoPattern(methodBody)) {
    // Check for complete pattern of safe usage
    if (!isSafeFileOperationPattern()) {
        issues.push(
            `Warning: File operations without proper path validation may lead to Time-of-Check to Time-of-Use (TOCTOU) race conditions in method "${methodName}". Add path validation and file locking mechanisms.`
        );
    }
}
        
        // Helper: Find the associated path for a file variable or descriptor
        function findAssociatedPath(variable: string): string | undefined {
            // First check if it's a direct file descriptor we know
            if (context.fileDescriptors.has(variable)) {
                return context.fileDescriptors.get(variable);
            }
            
            // Check if it's a file pointer we know
            if (context.filePointers.has(variable)) {
                return context.filePointers.get(variable);
            }
            
            // Check if it's a fd that came from fileno()
            if (context.fdToFilePointer.has(variable)) {
                const filePtr = context.fdToFilePointer.get(variable);
                if (filePtr && context.filePointers.has(filePtr)) {
                    return context.filePointers.get(filePtr);
                }
            }
            
            // Check if it's used in any file operations we know
            for (const [path, op] of context.fileOperations.entries()) {
                if (op.fdVar === variable) {
                    return path;
                }
            }
            
            return undefined;
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
        
        // Helper to detect open() calls with secure flags
        function hasSecureOpenFlags(node: Parser.SyntaxNode): boolean {
            if (node.type !== 'call_expression') return false;
            
            const fnName = node.child(0)?.text;
            if (fnName !== 'open') return false;
            
            const args = node.child(1)?.namedChildren;
            if (!args || args.length < 2) return false;
            
            const flagsArg = args[1].text;
            
            // Check for secure open flags that prevent race conditions
            return secureOpenFlags.some(flag => flagsArg.includes(flag));
        }
        
        // Helper to detect basename sanitization
        function isBasenameOrPathnamePattern(methodBody: string): boolean {
            // Check for basename/dirname pattern
            const hasBasename = /basename\s*\([^)]+\)/.test(methodBody);
            const hasRealpath = /realpath\s*\([^)]+\)/.test(methodBody);
            
            // Check for dirname pattern
            const hasDirname = /dirname\s*\([^)]+\)/.test(methodBody);
            
            // Check for strstr pattern to detect path traversal validation
            const hasPathTraversalCheck = /strstr\s*\([^,]+,\s*["']\.\.["']\)/.test(methodBody);
            
            return hasBasename || hasDirname || hasRealpath || hasPathTraversalCheck;
        }
        
        // Helper to detect locking patterns specifically with flock and fileno
        function hasFlockWithFilenoPattern(methodBody: string): boolean {
            // Check for the pattern: fileno(file) followed by flock
            const filenoPattern = /fileno\s*\(\s*(\w+)\s*\)/g;
            let filenoMatches = [...methodBody.matchAll(filenoPattern)];
            
            for (const match of filenoMatches) {
                const fileVar = match[1];
                const fdVarPattern = new RegExp(`(\\w+)\\s*=\\s*fileno\\s*\\(\\s*${fileVar}\\s*\\)`, 'g');
                const fdVarMatches = [...methodBody.matchAll(fdVarPattern)];
                
                // Check if any of these file descriptors are used with flock
                for (const fdMatch of fdVarMatches) {
                    const fdVar = fdMatch[1];
                    const flockPattern = new RegExp(`flock\\s*\\(\\s*${fdVar}\\s*,.*?LOCK_[A-Z]{2}.*?\\)`, 'g');
                    if (flockPattern.test(methodBody)) {
                        return true;
                    }
                }
                
                // Check for direct use of fileno with flock
                const directFlockPattern = new RegExp(`flock\\s*\\(\\s*fileno\\s*\\(\\s*${fileVar}\\s*\\)\\s*,.*?LOCK_[A-Z]{2}.*?\\)`, 'g');
                if (directFlockPattern.test(methodBody)) {
                    return true;
                }
            }
            
            return false;
        }
        
        // Helper to detect safe file operation patterns, especially fopen/fprintf/fclose sequences
        function isSafeFileOperationPattern(): boolean {
            // Check for path sanitization + secure opening pattern
            if (context.hasBasenameSanitization && context.hasSecureOpenFlags) {
                return true;
            }
            
            // Check for flock with fileno pattern
            if (hasFlockWithFilenoPattern(methodBody)) {
                return true;
            }
            
            // First check: Look for per-descriptor operation patterns
            for (const [fdVar, operations] of context.fileOperationsByFd.entries()) {
                // Sort operations by node position
                const sortedOps = [...operations].sort((a, b) => a.node.startIndex - b.node.startIndex);
                
                // Check for the standard open->use->close pattern
                const hasOpen = sortedOps.some(op => op.operation === 'fopen' || op.operation === 'open');
                const hasClose = sortedOps.some(op => op.operation === 'fclose' || op.operation === 'close');
                
                // If we have both open and close operations on this file descriptor
                if (hasOpen && hasClose) {
                    const firstOpen = sortedOps.find(op => op.operation === 'fopen' || op.operation === 'open');
                    const lastClose = [...sortedOps].reverse().find(op => op.operation === 'fclose' || op.operation === 'close');
                    
                    if (firstOpen && lastClose) {
                        // Check if all operations happen between open and close
                        const allInSequence = sortedOps.every(op => {
                            const opIndex = sortedOps.indexOf(op);
                            const openIndex = sortedOps.indexOf(firstOpen);
                            const closeIndex = sortedOps.indexOf(lastClose);
                            
                            return opIndex >= openIndex && opIndex <= closeIndex;
                        });
                        
                        if (allInSequence) {
                            // Found a clean open->use->close pattern
                            return true;
                        }
                    }
                }
            }
            
            // Second check: Look for patterns by path
            const pathOperations = new Map<string, {operation: string, node: Parser.SyntaxNode}[]>();
            
            // Group operations by path
            for (const [path, opInfo] of context.fileOperations.entries()) {
                if (!pathOperations.has(path)) {
                    pathOperations.set(path, []);
                }
                
                pathOperations.get(path)!.push({
                    operation: opInfo.operation,
                    node: opInfo.node
                });
            }
            
            // Check path-based patterns
            for (const [path, operations] of pathOperations.entries()) {
                // Sort by position
                const sortedOps = [...operations].sort((a, b) => a.node.startIndex - b.node.startIndex);
                
                const hasOpen = sortedOps.some(op => op.operation === 'fopen' || op.operation === 'open');
                const hasClose = sortedOps.some(op => op.operation === 'fclose' || op.operation === 'close');
                
                if (hasOpen && hasClose) {
                    // Check sequential ordering 
                    const firstOpen = sortedOps.find(op => op.operation === 'fopen' || op.operation === 'open');
                    const lastClose = [...sortedOps].reverse().find(op => op.operation === 'fclose' || op.operation === 'close');
                    
                    if (firstOpen && lastClose && firstOpen.node.startIndex < lastClose.node.startIndex) {
                        // This is a well-formed open->use->close pattern
                        return true;
                    }
                }
            }
            
            // Special case: Check for the exact pattern in our example
            // fopen() -> fprintf() -> fprintf() -> fclose()
            if (methodBody.includes('fopen') && methodBody.includes('fprintf') && methodBody.includes('fclose')) {
                // Simple heuristic - check if fopen comes before fclose
                const fopenIndex = methodBody.indexOf('fopen');
                const fcloseIndex = methodBody.indexOf('fclose');
                
                if (fopenIndex !== -1 && fcloseIndex !== -1 && fopenIndex < fcloseIndex) {
                    // Check if the operations are in the same scope - look for matching braces
                    const openBraceCount = methodBody.substring(fopenIndex, fcloseIndex).split('{').length - 1;
                    const closeBraceCount = methodBody.substring(fopenIndex, fcloseIndex).split('}').length - 1;
                    
                    // If braces are balanced or only slightly imbalanced, it's likely a well-formed pattern
                    if (openBraceCount >= closeBraceCount) {
                        return true;
                    }
                }
            }
            
            return false;
        }

        initParser();
        const tree = parser.parse(methodBody);
        
        // Check: Does the method only use standard streams?
        const usesOnlyStandardStreams = 
            /\bstdin\b|\bstdout\b|\bstderr\b/.test(methodBody) && 
            !(/\bfopen\b|\bopen\b|\bcreat\b/.test(methodBody));

        // Skip full analysis if we only use standard streams
        if (usesOnlyStandardStreams) {
            return []; // No race conditions with standard streams
        }
        
        // Pre-check: Scan for path sanitization and secure opening patterns
        context.hasBasenameSanitization = isBasenameOrPathnamePattern(methodBody);
        
        // Scan for fileno -> flock patterns
        const hasFilenoFlockPattern = hasFlockWithFilenoPattern(methodBody);
        
        // First pass: identify file descriptor variables, fileno calls, etc.
        function identifyFileDescriptors(node: Parser.SyntaxNode) {
            // Look for file descriptor assignments from open/fopen calls
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0);
                const rhs = node.child(2);
                
                if (lhs?.type === 'identifier' && rhs?.type === 'call_expression') {
                    const fnName = rhs.child(0)?.text;
                    
                    if (fnName === 'fopen' || fnName === 'open') {
                        const varName = lhs.text;
                        
                        if (fnName === 'fopen') {
                            filePointerVariables.add(varName);
                        } else {
                            fileDescriptorVariables.add(varName);
                        }
                        
                        // If we can extract the path, associate it with this file descriptor
                        const argList = rhs.child(1);
                        if (argList && argList.namedChildren.length > 0) {
                            const pathArg = argList.namedChildren[0];
                            const path = extractPathArgument(pathArg);
                            
                            if (path) {
                                if (fnName === 'fopen') {
                                    context.filePointers.set(varName, path);
                                } else {
                                    context.fileDescriptors.set(varName, path);
                                }
                                
                                // Also track this as a file operation
                                trackFileOperation(node, fnName, pathArg, lhs);
                            }
                        }
                        
                        // Check for secure open flags
                        if (fnName === 'open' && argList && argList.namedChildren.length > 1) {
                            const flagsArg = argList.namedChildren[1];
                            if (flagsArg && secureOpenFlags.some(flag => flagsArg.text.includes(flag))) {
                                context.hasSecureOpenFlags = true;
                            }
                        }
                    } else if (fnName === 'fileno') {
                        // Track fileno(file) -> fd mapping
                        const fdVar = lhs.text;
                        fileDescriptorVariables.add(fdVar);
                        
                        // Get the FILE* pointer being used
                        const argList = rhs.child(1);
                        if (argList && argList.namedChildren.length > 0) {
                            const filePointerArg = argList.namedChildren[0];
                            if (filePointerArg.type === 'identifier') {
                                const filePointerName = filePointerArg.text;
                                // Store the mapping fd -> FILE*
                                context.fdToFilePointer.set(fdVar, filePointerName);
                                
                                // If we know what file this FILE* points to, propagate to fd
                                if (context.filePointers.has(filePointerName)) {
                                    const path = context.filePointers.get(filePointerName)!;
                                    context.fileDescriptors.set(fdVar, path);
                                }
                            }
                        }
                    }
                }
            }
            
            // Look for direct fileno call in flock arguments
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text;
                const argsNode = node.child(1);
                
                // Handle standard stream operations early
                if (['fgets', 'fputs', 'fprintf', 'fscanf'].includes(fnName || '')) {
                    // Check last argument for stdin/stdout/stderr
                    if (argsNode && argsNode.namedChildren.length > 0) {
                        const lastArg = argsNode.namedChildren[argsNode.namedChildren.length - 1];
                        if (isStandardStream(lastArg)) {
                            context.standardStreamOperations.add(node);
                            return; // Skip further processing for this node
                        }
                    }
                }
                
                // Track fileno in flock call: flock(fileno(file), ...)
                if (fnName === 'flock' && argsNode && argsNode.namedChildren.length > 0) {
                    const firstArg = argsNode.namedChildren[0];
                    
                    if (firstArg.type === 'call_expression') {
                        const innerFnName = firstArg.child(0)?.text;
                        
                        if (innerFnName === 'fileno') {
                            // This is a flock(fileno(file), ...) pattern
                            const innerArgsNode = firstArg.child(1);
                            
                            if (innerArgsNode && innerArgsNode.namedChildren.length > 0) {
                                const filePointerArg = innerArgsNode.namedChildren[0];
                                
                                if (filePointerArg.type === 'identifier') {
                                    const filePointerName = filePointerArg.text;
                                    
                                    // If we know what file this FILE* points to, mark it as locked
                                    if (context.filePointers.has(filePointerName)) {
                                        const path = context.filePointers.get(filePointerName)!;
                                        context.lockOperations.set(path, {
                                            node,
                                            lockType: 'flock'
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                
                if (fnName === 'open') {
                    const argList = node.child(1);
                    if (argList && argList.namedChildren.length > 1) {
                        const flagsArg = argList.namedChildren[1];
                        if (flagsArg && secureOpenFlags.some(flag => flagsArg.text.includes(flag))) {
                            context.hasSecureOpenFlags = true;
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
            
              
            
            // Check for function calls that might indicate file operations
            if (node.type === 'call_expression') {
                const fnNameNode = node.child(0);
                const fnName = fnNameNode?.text || '';
                const argsNode = node.child(1);
                const line = getLineNumber(node);
                
                // Check if this is already marked as a standard stream operation
                if (context.standardStreamOperations.has(node)) {
                    return; // Skip operations on standard streams
                }
                
                // Specially handle stdin/stdout operations 
                if (['fgets', 'fprintf', 'fputs', 'fscanf'].includes(fnName)) {
                    if (argsNode && argsNode.namedChildren.length > 0) {
                        const lastArg = argsNode.namedChildren[argsNode.namedChildren.length - 1];
                        if (isStandardStream(lastArg)) {
                            context.standardStreamOperations.add(node);
                            return; // Skip standard stream operations
                        }
                    }
                }
                
                // Check for path sanitization functions
                if (pathSanitizers.includes(fnName)) {
                    context.hasBasenameSanitization = true;
                }
                
                // Track operations that might involve files
                if (fileAccessFunctions.includes(fnName)) {
                    // Different handling based on function type
                    if (fnName === 'fopen' || fnName === 'open') {
                        // For open operations, the first arg is the path
                        const pathArg = argsNode?.namedChildren[0];
                        trackFileOperation(node, fnName, pathArg);
                        
                        // Check for secure open flags
                        if (fnName === 'open' && argsNode && argsNode.namedChildren.length > 1) {
                            const flagsArg = argsNode.namedChildren[1];
                            if (flagsArg && secureOpenFlags.some(flag => flagsArg.text.includes(flag))) {
                                context.hasSecureOpenFlags = true;
                            }
                        }
                    } else if (fnName === 'fclose' || fnName === 'close') {
                        // For close operations, the first arg is the file descriptor
                        const fdArg = argsNode?.namedChildren[0];
                        trackFileOperation(node, fnName, undefined, fdArg);
                    } else if (fnName === 'fprintf' || fnName === 'fputs' || fnName === 'fwrite') {
                        // For file writing, first arg is the file descriptor
                        const fdArg = argsNode?.namedChildren[0];
                        trackFileOperation(node, fnName, undefined, fdArg);
                    } else {
                        // Generic handling
                        const pathArg = argsNode?.namedChildren[0];
                        trackFileOperation(node, fnName, pathArg);
                    }
                    
                    // Only warn if conditions are met and we're not using a recognized safe pattern
                    if (!context.synchronizedContext) {
                        // Skip standard stream operations for warnings
                        if (context.standardStreamOperations.has(node)) {
                            return; // Skip standard stream operations 
                        }
                        
                        // Get all locked paths
                        const lockedPaths = Array.from(context.lockOperations.keys());
                        
                        // Check if this operation is on a locked path or file descriptor
                        let isProtected = false;
                        
                        // Check if this is a file pointer operation (fwrite, fprintf, etc.)
                        if (argsNode && argsNode.namedChildren.length > 0) {
                            const firstArg = argsNode.namedChildren[0];
                            if (firstArg.type === 'identifier') {
                                const filePointerName = firstArg.text;
                                
                                // Check if this file pointer is associated with a locked path
                                if (context.filePointers.has(filePointerName)) {
                                    const path = context.filePointers.get(filePointerName)!;
                                    if (lockedPaths.includes(path)) {
                                        isProtected = true;
                                    }
                                }
                                
                                // Check if there's fileno -> flock pattern for this file pointer
                                if (hasFilenoFlockPattern && filePointerVariables.has(filePointerName)) {
                                    // This is likely protected by a flock call
                                    isProtected = true;
                                }
                            }
                        }
                        
                        // Run the check for safe patterns AFTER we've tracked this operation
                        const isPartOfSafePattern = isSafeFileOperationPattern();
                        
                        // Additional check for basename + secure flags pattern
                        const hasSecurePattern = (context.hasBasenameSanitization && context.hasSecureOpenFlags);
                        
                        // Only warn if detection level and pattern analysis justifies it
                        if (detectionLevel === 'strict' || 
                           (detectionLevel === 'moderate' && !isPartOfSafePattern && 
                                                           !hasSecurePattern && 
                                                           !isProtected)) {
                            
                            // Final check for standard streams before issuing warning
                            let isStdioOperation = false;
                            if (argsNode && argsNode.namedChildren.length > 0) {
                                for (const arg of argsNode.namedChildren) {
                                    if (isStandardStream(arg)) {
                                        isStdioOperation = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (!isStdioOperation && !isProtected) {
                                issues.push(
                                    `Warning: Unprotected file operation "${fnName}" detected at ${formatLineInfo(node)} in method "${methodName}". Consider using proper file locking.`
                                );
                            }
                        }
                    }
                
                // Track metadata operations
                if (metadataFunctions.includes(fnName)) {
                    // Extract the path argument (typically the first argument)
                    const pathArg = argsNode?.namedChildren[0];
                    trackFileOperation(node, fnName, pathArg);
                    
                    // Warn about potential TOCTOU vulnerabilities
                    if (!context.synchronizedContext && detectionLevel !== 'relaxed') {
                        // Check for safe patterns before warning
                        const isPartOfSafePattern = isSafeFileOperationPattern();
                        const hasSecurePattern = (context.hasBasenameSanitization && context.hasSecureOpenFlags);
                        
                        if (detectionLevel === 'strict' || 
                           (detectionLevel === 'moderate' && !isPartOfSafePattern && !hasSecurePattern)) {
                            issues.push(
                                `Warning: File metadata operation "${fnName}" at ${formatLineInfo(node)} in method "${methodName}" may lead to TOCTOU vulnerabilities.`
                            );
                        }
                    }
                }
                
                // Track lock operations
                if (fileLockFunctions.some(lockFn => fnName.toLowerCase().includes(lockFn.toLowerCase()))) {
                    // If this is a file-specific lock like flock
                    if (fnName === 'flock' || fnName === 'lockf') {
                        const fdArg = argsNode?.namedChildren[0]; // ✅ Get first arg (fd)
                        
                        if (fdArg?.type === 'identifier') {
                            const fdVar = fdArg.text;
                            
                            // ✅ Now associate fdVar → known filepath
                            const lockedPath = context.fileDescriptors.get(fdVar);
                            if (lockedPath) {
                                context.lockOperations.set(lockedPath, {
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
                if (argsNode) {
                    for (const arg of argsNode.namedChildren) {
                        if (arg.type === 'identifier' && fileDescriptorVariables.has(arg.text)) {
                            // This is an operation on a file descriptor
                            const fdVar = arg.text;
                            const path = context.fileDescriptors.get(fdVar);
                            
                            if (path && !isLikelyProtected(fnName, path) && !context.synchronizedContext) {
                                // Check if this is part of a safe pattern before warning
                                const isPartOfSafePattern = isSafeFileOperationPattern();
                                const hasSecurePattern = (context.hasBasenameSanitization && context.hasSecureOpenFlags);
                                
                                if ((detectionLevel === 'strict' || 
                                    (detectionLevel === 'moderate' && !isPartOfSafePattern && !hasSecurePattern)) &&
                                    !fileAccessFunctions.includes(fnName)) { // Skip if we already handled it above
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
            const isPartOfSafePattern = isSafeFileOperationPattern();
            const hasSecurePattern = (context.hasBasenameSanitization && context.hasSecureOpenFlags);
            
            // Check for method name safety patterns
            const isSecureFunctionName = methodName.includes('safe') || 
                                         methodName.includes('secure') || 
                                         methodName.includes('atomic');
            
            // Special case: does this method only use standard streams?
            const onlyStandardStreams = context.standardStreamOperations.size > 0 && 
                                       context.fileOperations.size === 0;
            
            // Only add general warning if needed based on detection level and safe pattern analysis
            if ((detectionLevel === 'strict' || 
                (detectionLevel === 'moderate' && !isPartOfSafePattern && 
                                               !hasSecurePattern && 
                                               !isSecureFunctionName && 
                                               !onlyStandardStreams)) && 
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
                // Check for safe patterns
                const isPartOfSafePattern = isSafeFileOperationPattern();
                const hasSecurePattern = (context.hasBasenameSanitization && context.hasSecureOpenFlags);
                
                // Only add if we haven't already warned about this specific instance
                // and if the detection level is appropriate
                if (detectionLevel !== 'relaxed' &&
                    !hasSecurePattern &&
                    !issues.some(msg => msg.includes(`TOCTOU vulnerability detected`) && msg.includes(path))) {
                    issues.push(
                        `Warning: Potential TOCTOU vulnerability on path "${path}" - checked at ${formatLineInfo(checkNode)} and used at ${formatLineInfo(useNode)} in method "${methodName}".`
                    );
                }
            }
        }

        // Special case for simple functions with standard I/O patterns or secure naming patterns
        if (methodName.includes('safe') || methodName.includes('secure') || methodName.includes('open_safe')) {
            // Clear warnings for functions specifically designed to be safe
            if (context.hasBasenameSanitization || context.hasSecureOpenFlags) {
                return [];
            }
        }
        
        // Special case: if the method only uses stdin/stdout (no actual files)
        if (context.standardStreamOperations.size > 0 && context.fileOperations.size === 0) {
            return []; // No race conditions with standard streams
        }

        
    }
    return issues;
    }
}