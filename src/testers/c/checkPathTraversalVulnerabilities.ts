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

// 🛠️ Escapes special characters for safe regex construction
function escapeRegex(str: string): string {
    return str.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
}

export class PathTraversalCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Track variables and their properties
        const taintedVariables = new Set<string>();
        const sanitizedVariables = new Set<string>();
        const validatedVariables = new Set<string>();
        const pathVariables = new Map<string, {value: string, line: number}>();
        const fileOperationCalls = new Map<string, {path: string, line: number}>();
        
        // Get configuration values
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const rawPatterns = config.get<string[]>('pathTraversalPatterns', [
            '../', '~/', '\\..\\', '..\\', '%2e%2e%2f', '%2e%2e/', '..%2f', '%2e%2e%5c'
        ]);
        const pathTraversalPatterns = rawPatterns.map(escapeRegex);
        
        const riskyFunctions = config.get<string[]>('riskyFunctions', [
            'fopen', 'readfile', 'open', 'opendir', 'readdir', 'writefile', 'unlink', 'rename', 
            'chmod', 'chown', 'mkdir', 'rmdir', 'symlink', 'readlink'
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

        initParser();
        const tree = parser.parse(methodBody);

        // Helper function to get line number
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }
        
        // 🔧 Input-specific sanitization checker - Enhanced with AST validation
        function isSanitized(input: string): boolean {
            // Check if the variable is in our sanitized set
            if (sanitizedVariables.has(input)) {
                return true;
            }
            
            // Check if the variable has been validated
            if (validatedVariables.has(input)) {
                return true;
            }
            
            // Variable name not found in sanitized or validated set
            return false;
        }
        
        // Check if a path contains traversal patterns
        function containsTraversalPattern(path: string): boolean {
            // Skip checking empty strings or null
            if (!path) return false;
            
            return rawPatterns.some(pattern => path.includes(pattern));
        }
        
        // Parse the AST and perform various checks
        function traverse(node: Parser.SyntaxNode) {
            // Handle string literals that might be paths
            if (node.type === 'string_literal') {
                const stringValue = node.text.replace(/["']/g, ''); // Remove quotes
                
                // Check if the string contains traversal patterns
                if (containsTraversalPattern(stringValue)) {
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
                            taintedVariables.add(name);
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
                        
                        // Track concatenation with traversal patterns
                        if (right.text.includes('..') || right.text.includes('~')) {
                            if (!sanitizedVariables.has(varName)) {
                                taintedVariables.add(varName);
                            }
                        }
                    }
                    
                    // Handle taint propagation (if right side is tainted, left becomes tainted)
                    if (right.type === 'identifier' && taintedVariables.has(right.text)) {
                        taintedVariables.add(varName);
                    }
                    
                    // Handle string concatenation (if contains traversal patterns)
                    if (right.type === 'binary_expression' && right.child(1)?.text === '+') {
                        const leftExpr = right.child(0)?.text || '';
                        const rightExpr = right.child(2)?.text || '';
                        
                        if (containsTraversalPattern(leftExpr) || containsTraversalPattern(rightExpr)) {
                            if (!sanitizedVariables.has(varName)) {
                                taintedVariables.add(varName);
                            }
                        }
                    }
                }
            }
            
            // Track path validations in if statements
            if (node.type === 'if_statement') {
                const condition = node.childForFieldName('condition');
                if (condition) {
                    // Check for validation patterns like if(strstr(path, "..") != NULL)
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
                    
                    // Also track variables that appear in any condition (might be validated)
                    const identifiers = condition.descendantsOfType('identifier');
                    for (const id of identifiers) {
                        if (taintedVariables.has(id.text)) {
                            validatedVariables.add(id.text);
                        }
                    }
                }
            }
            
            // Check function calls
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const args = node.child(1)?.namedChildren || [];
                const line = getLineNumber(node);
                
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
                
                // File inclusion functions can also lead to path traversal
                if (fileInclusions.includes(fnName)) {
                    if (args.length > 0) {
                        const includeArg = args[0];
                        
                        // Check for direct traversal patterns in includes
                        if (includeArg.type === 'string_literal' && containsTraversalPattern(includeArg.text)) {
                            issues.push(
                                `Warning: Path traversal vulnerability in file inclusion "${fnName}" at line ${line} in method "${methodName}". Avoid relative paths in includes.`
                            );
                        }
                        // Check for variables that might contain traversal patterns
                        else if (includeArg.type === 'identifier') {
                            const varName = includeArg.text;
                            
                            if ((pathVariables.has(varName) || taintedVariables.has(varName)) && !isSanitized(varName)) {
                                issues.push(
                                    `Warning: Potential path traversal in file inclusion "${fnName}" with variable "${varName}" at line ${line} in method "${methodName}". Sanitize paths before including files.`
                                );
                            }
                        }
                    }
                }
            }
            
            // Recursively traverse children
            node.namedChildren.forEach(traverse);
        }
        
        // 🔹 Phase 1: Regex Pattern-based Traversal Detection for quick wins
        const pathTraversalPattern = new RegExp(`(${pathTraversalPatterns.join('|')})`, 'g');
        let match;
        while ((match = pathTraversalPattern.exec(methodBody)) !== null) {
            // We'll still keep this but as an initial flag only - detailed contextual analysis is done in the AST
            const path = match[1];
            issues.push(
                `Warning: Potential Path Traversal pattern "${path}" detected in method "${methodName}". Avoid using relative paths with user input.`
            );
        }
        
        // 🔹 Phase 2: Execute AST-based analysis
        traverse(tree.rootNode);
        
        // 🔹 Phase 3: Final pass to check for any file operations without adequate checks
        fileOperationCalls.forEach(({path, line}, key) => {
            // Skip if we've already flagged this operation
            if (issues.some(issue => issue.includes(`at line ${line}`) && issue.includes(path))) {
                return;
            }
            
            // Check if the path is a variable that hasn't been sanitized or validated
            if (path && !path.startsWith('"') && !path.startsWith("'") && 
                !isSanitized(path) && taintedVariables.has(path)) {
                issues.push(
                    `Warning: Unsanitized input "${path}" detected in file operation at line ${line} in method "${methodName}". Ensure input is sanitized before use.`
                );
            }
        });
        
        return issues;
    }
}