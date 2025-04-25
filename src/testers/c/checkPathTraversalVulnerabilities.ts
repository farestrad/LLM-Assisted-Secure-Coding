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

// Helper function for cleaner regex escaping
function escapeRegex(str: string): string {
    return str.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
}

export class PathTraversalCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Get configuration values
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        
        // IMPROVEMENT: Early detection of file operations - if none, exit early
        const fileOperationPattern = /\b(fopen|open|readfile|writefile|unlink|rename|access|stat|realpath)\b/;
        const pathOperationPattern = /(\/|\\|\.\.)/;
        
        // IMPROVEMENT: Skip analysis entirely if no file operations or path patterns present
        if (!fileOperationPattern.test(methodBody) && !pathOperationPattern.test(methodBody)) {
            return []; // No file operations, no need to check for path traversal
        }
        
        const rawPatterns = config.get<string[]>('pathTraversalPatterns', [
            '../', '~/', '\\..\\', '..\\', '%2e%2e%2f', '%2e%2e/', '..%2f', '%2e%2e%5c'
        ]);
        
        // IMPROVEMENT: Filter out patterns that trigger false positives in standard functions
        const pathTraversalPatterns = rawPatterns
            .filter(pattern => {
                // Exclude patterns that may appear in standard function names/comments
                if (pattern === '..\\'  && 
                    !methodBody.includes('..\\') && 
                    !methodBody.includes('path')) {
                    return false;
                }
                return true;
            })
            .map(escapeRegex);
        
        const riskyFunctions = config.get<string[]>('riskyFunctions', [
            'fopen', 'readfile', 'open', 'opendir', 'readdir', 'writefile', 'unlink', 'rename', 
            'chmod', 'chown', 'mkdir', 'rmdir', 'symlink', 'readlink', 'realpath'
        ]);
        
        const commandExecFunctions = config.get<string[]>('commandExecFunctions', [
            'system', 'popen', 'exec', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe'
        ]);
        
        const fileInclusions = config.get<string[]>('fileInclusions', [
            'include', 'require', 'include_once', 'require_once', 'import'
        ]);
        
        const sanitizationFunctions = config.get<string[]>('sanitizationFunctions', [
            'realpath', 'basename', 'dirname', 'escapeshellarg', 'escapeshellcmd', 
            'sanitize_filename', 'sanitize_path', 'canonicalize_path'
        ]);
        
        const validationPatterns = config.get<string[]>('validationPatterns', [
            'strstr', 'strpos', 'strchr', 'strrchr', 'strcmp', 'strcasecmp', 'strncmp', 'strncasecmp'
        ]);

        // Track variables and their properties
        const taintedVariables = new Set<string>();
        const sanitizedVariables = new Set<string>();
        const validatedVariables = new Set<string>();
        const pathVariables = new Map<string, {value: string, line: number}>();
        const fileOperationCalls = new Map<string, {path: string, line: number}>();
        
        // IMPROVEMENT: Track if file operations are actually present 
        let hasFileOperations = false;
        
        initParser();
        const tree = parser.parse(methodBody);

        // Helper function to get line number
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }
        
        // IMPROVEMENT: More careful sanitization checking
        function isSanitized(input: string): boolean {
            if (sanitizedVariables.has(input)) {
                return true;
            }
            
            if (validatedVariables.has(input)) {
                return true;
            }
            
            return false;
        }
        
        // IMPROVEMENT: More careful traversal pattern detection
        function containsTraversalPattern(path: string): boolean {
            if (!path) return false;
            
            // Skip checking if path is a standard stream
            if (['stdin', 'stdout', 'stderr'].includes(path)) {
                return false;
            }
            
            return rawPatterns.some(pattern => path.includes(pattern));
        }
        
        // First pass - just find if there are any file operations at all
        function detectFileOperations(node: Parser.SyntaxNode) {
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                
                // Check for file operation functions
                if (riskyFunctions.includes(fnName) || commandExecFunctions.includes(fnName)) {
                    hasFileOperations = true;
                    return; // Early exit once we find one
                }
            }
            
            node.namedChildren.forEach(detectFileOperations);
        }
        
        // First do a quick scan for file operations
        detectFileOperations(tree.rootNode);
        
        // IMPROVEMENT: If no file operations, we can exit early
        if (!hasFileOperations) {
            return [];
        }
        
        // Main traverse function for detailed analysis
        function traverse(node: Parser.SyntaxNode) {
            // Check string literals that might be paths
            if (node.type === 'string_literal') {
                const stringValue = node.text.replace(/["']/g, ''); // Remove quotes
                
                // Only care about strings with traversal patterns in file contexts
                if (containsTraversalPattern(stringValue) && hasFileOperations) {
                    if (node.parent?.type === 'assignment_expression') {
                        const assignTo = node.parent.child(0)?.text;
                        if (assignTo) {
                            pathVariables.set(assignTo, {
                                value: stringValue,
                                line: getLineNumber(node)
                            });
                        }
                    }
                }
            }
            
            // Track variable declarations with path assignments
            if (node.type === 'declaration') {
                const declarators = node.descendantsOfType('init_declarator');
                for (const declarator of declarators) {
                    const name = declarator.childForFieldName('declarator')?.text;
                    const value = declarator.childForFieldName('value');
                    
                    // String literals with traversal patterns
                    if (name && value?.type === 'string_literal') {
                        const stringValue = value.text.replace(/["']/g, ''); // Remove quotes
                        if (containsTraversalPattern(stringValue)) {
                            pathVariables.set(name, {
                                value: stringValue,
                                line: getLineNumber(declarator)
                            });
                        }
                    }
                    
                    // User input sources (mark as tainted)
                    if (name && value?.type === 'call_expression') {
                        const fnName = value.child(0)?.text;
                        if (['gets', 'fgets', 'scanf', 'fscanf', 'recv', 'read'].includes(fnName || '')) {
                            // IMPROVEMENT: Don't mark variables from stdin as tainted
                            const args = value.child(1)?.namedChildren || [];
                            const isStdin = args.length > 0 && 
                                           args[args.length - 1]?.type === 'identifier' && 
                                           args[args.length - 1]?.text === 'stdin';
                            
                            if (!isStdin) {
                                taintedVariables.add(name);
                            }
                        }
                    }
                }
            }

            // Track assignment expressions
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const right = node.child(2);
                
                if (left?.type === 'identifier' && right) {
                    const varName = left.text;
                    const line = getLineNumber(node);
                    
                    // Track string assignments with traversal patterns
                    if (right.type === 'string_literal') {
                        const stringValue = right.text.replace(/["']/g, ''); // Remove quotes
                        if (containsTraversalPattern(stringValue)) {
                            pathVariables.set(varName, {
                                value: stringValue,
                                line: getLineNumber(node)
                            });
                        }
                    }
                    
                    // Track sanitization function calls
                    if (right.type === 'call_expression') {
                        const fnName = right.child(0)?.text;
                        
                        // Mark variables sanitized by known functions
                        if (sanitizationFunctions.includes(fnName || '')) {
                            sanitizedVariables.add(varName);
                        }
                        
                        // IMPROVEMENT: Don't mark stdin operations as tainted
                        if (fnName === 'fgets' || fnName === 'fscanf') {
                            const args = right.child(1)?.namedChildren || [];
                            const lastArg = args[args.length - 1];
                            
                        }
                        
                        // Track concatenation with traversal patterns
                        if (right.text.includes('..') || right.text.includes('~/')) {
                            if (!sanitizedVariables.has(varName)) {
                                taintedVariables.add(varName);
                            }
                        }
                    }
                    
                    // Handle taint propagation (if right side is tainted, left becomes tainted)
                    if (right.type === 'identifier' && taintedVariables.has(right.text)) {
                        taintedVariables.add(varName);
                    }
                }
            }
            
            // Track path validations in if statements
            if (node.type === 'if_statement') {
                const condition = node.childForFieldName('condition');
                if (condition) {
                    // Check for validation patterns
                    const validationCall = condition.descendantsOfType('call_expression')
                        .find(call => {
                            const fnName = call.child(0)?.text;
                            return validationPatterns.includes(fnName || '');
                        });
                    
                    if (validationCall) {
                        const args = validationCall.child(1)?.namedChildren || [];
                        for (const arg of args) {
                            if (arg.type === 'identifier') {
                                validatedVariables.add(arg.text);
                            }
                        }
                    }
                    
                    // Track variables that appear in any condition (might be validated)
                    const identifiers = condition.descendantsOfType('identifier');
                    for (const id of identifiers) {
                        if (taintedVariables.has(id.text)) {
                            validatedVariables.add(id.text);
                        }
                    }
                }
            }
            
            // IMPROVEMENT: Much more careful file operation detection
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const args = node.child(1)?.namedChildren || [];
                const line = getLineNumber(node);
                
                // Skip any analysis on standard I/O functions with stdin/stdout
                if ((fnName === 'fgets' || fnName === 'fprintf' || fnName === 'fputs') && 
                    args.length > 0 && 
                    args[args.length - 1]?.type === 'identifier' && 
                    ['stdin', 'stdout', 'stderr'].includes(args[args.length - 1]?.text)) {
                    // Standard I/O operation, not a file - skip this
                    node.namedChildren.forEach(traverse);
                    return;
                }
                
                // Check if it's a sanitization function
                if (sanitizationFunctions.includes(fnName)) {
                    if (args.length > 0 && args[0].type === 'identifier') {
                        sanitizedVariables.add(args[0].text);
                    }
                }
                
                // Check for risky functions that may lead to path traversal
                if (riskyFunctions.includes(fnName)) {
                    // Get the first argument (typically the path)
                    if (args.length > 0) {
                        const pathArg = args[0];
                        
                        // Add to our file operations map
                        fileOperationCalls.set(fnName + line, {
                            path: pathArg.text,
                            line
                        });
                        
                        // Check for direct traversal patterns in string literals
                        if (pathArg.type === 'string_literal') {
                            const pathValue = pathArg.text.replace(/["']/g, '');
                            if (containsTraversalPattern(pathValue)) {
                                issues.push(
                                    `Warning: Path traversal vulnerability detected in function "${fnName}" in method "${methodName}" at line ${line} with argument "${pathValue}". Avoid using relative paths with user input.`
                                );
                            }
                        }
                        // Check for variables that contain traversal patterns
                        else if (pathArg.type === 'identifier') {
                            const varName = pathArg.text;
                            
                            
                            
                            // If it's a path variable we've tracked and it's not sanitized
                            if (pathVariables.has(varName) && !isSanitized(varName)) {
                                issues.push(
                                    `Warning: Path traversal vulnerability detected in function "${fnName}" in method "${methodName}" at line ${line} with argument "${varName}" containing "${pathVariables.get(varName)?.value}". Avoid using relative paths with user input.`
                                );
                            }
                            // If it's a tainted variable from user input and not sanitized
                            else if (taintedVariables.has(varName) && !isSanitized(varName)) {
                                issues.push(
                                    `Warning: Unsanitized user input "${varName}" used in file operation "${fnName}" at line ${line} in method "${methodName}". Ensure input is sanitized before use.`
                                );
                            }
                        }
                    }
                }
                
                // Command execution functions with potential path traversal
                if (commandExecFunctions.includes(fnName)) {
                    if (args.length > 0) {
                        const cmdArg = args[0];
                        
                        // Skip warning if it's a standard stream
                        
                        
                        // Check for command injection with path traversal
                        if ((cmdArg.type === 'string_literal' && containsTraversalPattern(cmdArg.text)) ||
                            (cmdArg.type === 'identifier' && (pathVariables.has(cmdArg.text) || taintedVariables.has(cmdArg.text)))) {
                            
                            // Check if the argument is sanitized
                            if (cmdArg.type === 'identifier' && !isSanitized(cmdArg.text)) {
                                issues.push(
                                    `Warning: Potential command injection with path traversal in function "${fnName}" at line ${line} in method "${methodName}". Argument "${cmdArg.text}" may contain traversal sequences. Sanitize input before use.`
                                );
                            } else if (cmdArg.type === 'string_literal') {
                                issues.push(
                                    `Warning: Command execution "${fnName}" contains path traversal patterns at line ${line} in method "${methodName}". Avoid using relative paths in commands.`
                                );
                            }
                        }
                    }
                }
            }
            
            // Continue traversing children
            node.namedChildren.forEach(traverse);
        }
        
        // Phase 1: Only do regex pattern checks if we have file operations 
        if (hasFileOperations) {
            const pathTraversalPattern = new RegExp(`(${pathTraversalPatterns.join('|')})`, 'g');
            let match;
            while ((match = pathTraversalPattern.exec(methodBody)) !== null) {
                // Only report if the pattern is in a string literal or user input context
                // This avoids false positives from comments and unrelated code
                const pattern = match[1];
                const context = methodBody.substring(Math.max(0, match.index - 20), 
                                                  Math.min(methodBody.length, match.index + pattern.length + 20));
                
                // Skip warning if the pattern is in a comment or appears to be in printf/logging
                if (context.includes('//') || context.includes('/*') || 
                    context.includes('printf') || context.includes('fprintf')) {
                    continue;
                }
                
                issues.push(
                    `Warning: Potential Path Traversal pattern "${pattern}" detected in method "${methodName}". Avoid using relative paths with user input.`
                );
            }
        }
        
        // Phase 2: Execute AST-based analysis
        traverse(tree.rootNode);
        
        return issues;
    }
}