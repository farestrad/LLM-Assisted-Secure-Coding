import * as vscode from 'vscode';
import { SecurityCheck } from "../c/SecurityCheck";
import Parser from 'tree-sitter';
import C from 'tree-sitter-c';

let parser: Parser;

function initParser() {
    if (!parser) {
        parser = new Parser();
        parser.setLanguage(C as unknown as Parser.Language);
    }
}

export class OtherVulnerabilitiesCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        
        // Get configuration values
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        
        // Command injection vulnerabilities
        const commandInjectionFunctions = config.get<string[]>('commandInjectionFunctions', [
            'system', 'popen', 'exec', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe',
            'ShellExecute', 'ShellExecuteEx', 'CreateProcess', 'WinExec'
        ]);
        
        // Credential-related keywords
        const hardcodedCredentialsKeywords = config.get<string[]>('hardcodedCredentialsKeywords', [
            'password', 'passwd', 'pwd', 'pass', 'secret', 'key', 'apikey', 'api_key', 'token', 
            'access_token', 'auth', 'credentials', 'secret_key', 'private_key', 'certificate'
        ]);
        
        // Weak crypto algorithms
        const weakCryptoAlgorithms = config.get<string[]>('weakCryptoAlgorithms', [
            'DES', 'des', 'RC4', 'rc4', 'RC2', 'rc2'
        ]);
        
       
        
        // Privilege management functions
        const improperPrivilegeFunctions = config.get<string[]>('improperPrivilegeFunctions', [
            'setuid', 'setgid', 'seteuid', 'setegid', 'chroot', 'AllowSetForegroundWindow',
            'ImpersonateLoggedOnUser', 'ImpersonateNamedPipeClient'
        ]);
        
        // Session management functions
        const improperSessionFunctions = config.get<string[]>('improperSessionFunctions', [
            'session_start', 'session_regenerate_id', 'session_destroy', 'session_id'
        ]);
        
        // Error handling functions
        const errorHandlingFunctions = config.get<string[]>('errorHandlingFunctions', [
            'perror', 'strerror', 'fprintf', 'vfprintf', 'syslog', 'FormatMessage'
        ]);
        
        // Insecure file operations
        const insecureFileOperations = config.get<string[]>('insecureFileOperations', [
            'chmod', 'chown', 'mktemp', 'tempnam', 'tmpnam', 'umask'
        ]);
        
        // Format string vulnerability functions
        const formatStringFunctions = config.get<string[]>('formatStringFunctions', [
            'printf', 'sprintf', 'fprintf', 'snprintf', 'vprintf', 'vsprintf', 'vfprintf', 'vsnprintf'
        ]);
        
        // Regular expressions for finding patterns
        const regexPatterns = [
            { pattern: /\b(==|!=|strcmp)\s*\(\s*["'].*["']\s*,\s*.*password.*\)/gi, 
              message: 'Insecure password comparison' },
            { pattern: /\bif\s*\(\s*user\.role\s*==\s*['"]admin['"]\s*\)/gi, 
              message: 'Insecure role-based authorization' },
            { pattern: /\b(HttpOnly|secure)\s*=\s*false\b/gi, 
              message: 'Insecure cookie settings' },
            { pattern: /\beval\s*\(/gi, 
              message: 'Dangerous eval() function' },
            { pattern: /\b(\w+)\s*\+=\s*\d+\s*;[\s\S]{1,50}\1\s*\+=\s*\d+/gi, 
              message: 'Potential time-of-check to time-of-use race condition' }
        ];
        
        // Initialize data structures for analysis
        const variableAssignments = new Map<string, { value: string, line: number, type: string }>();
        const functionCalls = new Map<string, { args: string[], line: number }>();
        const credentialVariables = new Set<string>();
        const trustedInputVars = new Set<string>();
        const untrustedInputVars = new Set<string>();
        
        // Initialize parser
        initParser();
        const tree = parser.parse(methodBody);
        
        // Helper function to get line number
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }
        
        // Helper function to check if a variable name includes credential keywords
        function isCredentialVariable(name: string): boolean {
            return hardcodedCredentialsKeywords.some(keyword => 
                name.toLowerCase().includes(keyword.toLowerCase())
            );
        }
        
        // Helper function to check if a string contains weak crypto algorithms
        function containsWeakCrypto(str: string): string | null {
            for (const algo of weakCryptoAlgorithms) {
                if (new RegExp(`\\b${algo}\\b`, 'i').test(str)) {
                    return algo;
                }
            }
            return null;
        }
        
        // Main AST traversal function
        function traverse(node: Parser.SyntaxNode) {
            switch (node.type) {
                case 'declaration': {
                    // Check for hardcoded credentials in variable declarations
                    const declarators = node.descendantsOfType('init_declarator');
                    for (const decl of declarators) {
                        const nameNode = decl.childForFieldName('declarator');
                        const valueNode = decl.childForFieldName('value');
                        
                        if (nameNode && valueNode) {
                            const name = nameNode.text;
                            const value = valueNode.text;
                            const line = getLineNumber(decl);
                            
                            // Track all variable assignments for later analysis
                            variableAssignments.set(name, { value, line, type: 'declaration' });
                            
                            // Check for credential variables
                            if (isCredentialVariable(name)) {
                                credentialVariables.add(name);
                                
                                // Check for hardcoded credentials
                                if (valueNode.type === 'string_literal') {
                                    issues.push(
                                        `Warning: Hardcoded credential detected for variable "${name}" at line ${line} in method "${methodName}". Credentials should not be hardcoded.`
                                    );
                                }
                            }
                            
                            // Check for weak crypto algorithms in declarations
                            const cryptoAlgo = containsWeakCrypto(name);
                            if (cryptoAlgo) {
                                issues.push(
                                    `Warning: Weak cryptographic algorithm "${cryptoAlgo}" detected in variable declaration at line ${line} in method "${methodName}". Use stronger algorithms like SHA-256 or better.`
                                );
                            }
                        }
                    }
                    break;
                }
                
                case 'assignment_expression': {
                    const left = node.child(0);
                    const right = node.child(2);
                    
                    if (left && right) {
                        const name = left.text;
                        const value = right.text;
                        const line = getLineNumber(node);
                        
                        // Track assignment for later analysis
                        variableAssignments.set(name, { value, line, type: 'assignment' });
                        
                        // Check for credential variables
                        if (isCredentialVariable(name)) {
                            credentialVariables.add(name);
                            
                            // Check for hardcoded credentials
                            if (right.type === 'string_literal') {
                                issues.push(
                                    `Warning: Hardcoded credential assigned to "${name}" at line ${line} in method "${methodName}". Credentials should not be hardcoded.`
                                );
                            }
                        }
                        
                        
                    }
                    break;
                }
                
                case 'call_expression': {
                    const fnNameNode = node.child(0);
                    const argsNode = node.child(1);
                    
                    if (fnNameNode && argsNode) {
                        const fnName = fnNameNode.text;
                        const line = getLineNumber(node);
                        const args: string[] = [];
                        
                        // Extract arguments
                        argsNode.namedChildren.forEach(arg => {
                            args.push(arg.text);
                        });
                        
                        // Track function calls for later analysis
                        functionCalls.set(`${fnName}_${line}`, { args, line });
                        
                        // 1. Command Injection Check
                        if (commandInjectionFunctions.includes(fnName)) {
                            const cmdArg = args[0] || '';
                            
                            // Check if argument is a variable that might contain user input
                            if (untrustedInputVars.has(cmdArg) || 
                                (cmdArg.includes('+') && !trustedInputVars.has(cmdArg))) {
                                issues.push(
                                    `Warning: Potential command injection vulnerability in "${fnName}" at line ${line} in method "${methodName}". Avoid passing unvalidated input to command execution functions.`
                                );
                            } else if (cmdArg.includes('$') || cmdArg.includes('`') || cmdArg.includes('%')) {
                                issues.push(
                                    `Warning: Command execution with variable substitution detected in "${fnName}" at line ${line} in method "${methodName}". Ensure proper validation of inputs.`
                                );
                            }
                        }
                      
                        // 3. Privilege Management Check
                        if (improperPrivilegeFunctions.includes(fnName)) {
                            // Check for risky privilege operations
                            if (args.length > 0 && (args[0] === '0' || args[0] === 'root')) {
                                issues.push(
                                    `Warning: Risky privilege management detected in call to "${fnName}" with argument "${args[0]}" at line ${line} in method "${methodName}". Avoid running with root/admin privileges when possible.`
                                );
                            } else {
                                issues.push(
                                    `Warning: Privilege management function "${fnName}" detected at line ${line} in method "${methodName}". Ensure proper permission controls are in place.`
                                );
                            }
                        }
                        
                        // 4. Session Management Check
                        if (improperSessionFunctions.includes(fnName)) {
                            issues.push(
                                `Warning: Session management function "${fnName}" detected at line ${line} in method "${methodName}". Ensure proper session security controls are implemented.`
                            );
                        }
                        
                        // 5. Error Handling Check
                        if (errorHandlingFunctions.includes(fnName)) {
                            const errorMsg = args.find(arg => arg.includes('error') || arg.includes('exception'));
                            if (errorMsg && credentialVariables.size > 0) {
                                issues.push(
                                    `Warning: Error handling at line ${line} in method "${methodName}" may expose sensitive information. Ensure error messages don't contain credentials or sensitive data.`
                                );
                            }
                        }
                        
                        // 6. Insecure File Operations Check
                        if (insecureFileOperations.includes(fnName)) {
                            issues.push(
                                `Warning: Insecure file operation "${fnName}" detected at line ${line} in method "${methodName}". This operation may lead to security vulnerabilities.`
                            );
                        }
                        
                        // 7. Format String Vulnerability Check
                        if (formatStringFunctions.includes(fnName) && args.length > 1) {
                            const formatString = args[0];
                            
                            // Check if format string is a variable (potential format string vulnerability)
                            if (!formatString.startsWith('"') && !formatString.startsWith("'") && 
                                !trustedInputVars.has(formatString)) {
                                issues.push(
                                    `Warning: Potential format string vulnerability detected in call to "${fnName}" at line ${line} in method "${methodName}". First argument should be a literal format string, not a variable.`
                                );
                            }
                            
                            // Check if format specifiers match argument count
                            if (formatString.startsWith('"') || formatString.startsWith("'")) {
                                const formatSpecifiers = formatString.match(/%[sdioxXufeEgGaAcsp]/g);
                                const specifierCount = formatSpecifiers ? formatSpecifiers.length : 0;
                                
                                if (specifierCount > args.length - 1) {
                                    issues.push(
                                        `Warning: Format string at line ${line} in method "${methodName}" has more format specifiers (${specifierCount}) than arguments (${args.length - 1}), which can lead to undefined behavior or crashes.`
                                    );
                                }
                            }
                        }
                        
                        // 8. Weak Crypto Check in function calls
                        const cryptoAlgo = containsWeakCrypto(fnName);
                        if (cryptoAlgo) {
                            issues.push(
                                `Warning: Weak cryptographic algorithm "${cryptoAlgo}" used in function call at line ${line} in method "${methodName}". Use stronger algorithms like SHA-256 or better.`
                            );
                        }
                    }
                    break;
                }
                
                case 'if_statement': {
                    const condition = node.childForFieldName('condition');
                    if (condition) {
                        const conditionText = condition.text;
                        
                        // Check for insecure authentication patterns
                        if ((/password/i.test(conditionText) || /credential/i.test(conditionText)) && 
                            (/==/.test(conditionText) || /!=/.test(conditionText) || /strcmp/.test(conditionText))) {
                            issues.push(
                                `Warning: Potentially insecure authentication comparison detected at line ${getLineNumber(condition)} in method "${methodName}". Use secure, timing-safe comparison functions for credentials.`
                            );
                        }
                        
                        // Check for role-based authorization issues
                        if (/role\s*==\s*["']admin["']/.test(conditionText) || 
                            /isAdmin\s*==\s*true/.test(conditionText)) {
                            issues.push(
                                `Warning: Insecure role-based authorization check detected at line ${getLineNumber(condition)} in method "${methodName}". Implement proper access controls.`
                            );
                        }
                        
                        // Mark variables used in conditions as potentially validated
                        condition.descendantsOfType('identifier').forEach(id => {
                            trustedInputVars.add(id.text);
                        });
                    }
                    break;
                }
                
                case 'binary_expression': {
                    // Check for weak crypto in expressions
                    const cryptoAlgo = containsWeakCrypto(node.text);
                    if (cryptoAlgo) {
                        issues.push(
                            `Warning: Weak cryptographic algorithm "${cryptoAlgo}" detected in expression at line ${getLineNumber(node)} in method "${methodName}". Use stronger algorithms like SHA-256 or better.`
                        );
                    }
                    break;
                }
                
                case 'preproc_include': {
                    const includePath = node.text.replace('#include', '').trim();
                    
                    // Check for including weak crypto headers
                    if (includePath.includes('md5.h') || includePath.includes('sha1.h') || 
                        includePath.includes('des.h') || includePath.includes('rc4.h') ||
                        includePath.includes('rc2.h')) {
                        issues.push(
                            `Warning: Including weak cryptographic library "${includePath}" at line ${getLineNumber(node)} in method "${methodName}". Use modern, secure cryptographic libraries.`
                        );
                    }
                    break;
                }
            }
            
            // Recursive traversal of child nodes
            node.namedChildren.forEach(child => traverse(child));
        }
        
        // Start AST traversal
        traverse(tree.rootNode);
        
        // Additional regex-based pattern checks
        regexPatterns.forEach(({pattern, message}) => {
            let match;
            while ((match = pattern.exec(methodBody)) !== null) {
                issues.push(
                    `Warning: ${message} detected in method "${methodName}". This pattern may lead to security vulnerabilities.`
                );
            }
        });
        
        // Post-processing logic for complex vulnerability patterns
        
        // Check for timing attack vulnerabilities in credential comparisons
        credentialVariables.forEach(credVar => {
            functionCalls.forEach(({args, line}, key) => {
                if (key.startsWith('strcmp') && args.includes(credVar)) {
                    issues.push(
                        `Warning: Potential timing attack vulnerability detected at line ${line} in method "${methodName}". Use constant-time comparison functions for credentials.`
                    );
                }
            });
        });
        
        // Look for variables used in both file operations and command execution
        const dualUsageVars = new Set<string>();
        functionCalls.forEach(({args}, key) => {
            if (key.startsWith('fopen') || key.startsWith('open')) {
                args.forEach(arg => {
                    functionCalls.forEach(({args: cmdArgs}, cmdKey) => {
                        if (commandInjectionFunctions.some(cmd => cmdKey.startsWith(cmd)) && 
                            cmdArgs.some(cmdArg => cmdArg.includes(arg))) {
                            dualUsageVars.add(arg);
                        }
                    });
                });
            }
        });
        
        dualUsageVars.forEach(varName => {
            issues.push(
                `Warning: Variable "${varName}" is used in both file operations and command execution in method "${methodName}". This could lead to potential command injection vulnerabilities.`
            );
        });
        
        return issues;
    }
}