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

export class PlaintextPasswordCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const passwordVariables = new Set<string>();
        const secureHandledVariables = new Set<string>(); // Track variables that are properly handled
        const connectionStrings = new Set<string>(); // Track connection strings containing passwords
        
        // Track context to reduce false positives
        const functionContext = {
            isSecurityContext: /auth|login|password|credential|secure/i.test(methodName),
            hasMemset: false, // Check for password clearing
            hasHashCall: false // Check for password hashing
        };

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        
        // Enhanced keyword detection with more specific patterns
        const passwordKeywords = config.get<string[]>('passwordkeywords', [
            'pass', 'password', 'passwd', 'pwd', 'user_password', 'admin_password',
            'auth_pass', 'login_password', 'secure_password', 'db_password',
            'secret_key', 'passphrase', 'master_password', 'credentials'
        ]);
        
        // Context keywords where "pass" is likely not a password
        const falsePositiveContexts = [
            'compass', 'bypass', 'passthrough', 'pass_by', 'passing', 
            'passenger', 'passport', 'pass_rate', 'pass_count', 'pass_flag'
        ];
        
        // Enhanced list of risky output functions
        const riskyWriteFunctions = [
            'fprintf', 'fwrite', 'fputs', 'write', 'printf', 'sprintf', 
            'snprintf', 'puts', 'fputc', 'vprintf', 'vfprintf'
        ];
        
        // Enhanced list of logging functions
        const riskyLogFunctions = [
            'log', 'console.log', 'System.out.println', 'logger', 'syslog',
            'log_info', 'log_debug', 'log_error'
        ];
        
        // Functions that might properly handle passwords
        const secureFunctions = [
            'hash', 'encrypt', 'crypt', 'bcrypt', 'scrypt', 'sha', 'md5',
            'memset', 'zero', 'verify', 'compare', 'check'
        ];
        
        // File operations that might expose passwords
        const fileOperations = [
            'fopen', 'open', 'ofstream', 'save', 'store', 'write_to_file'
        ];

        initParser();
        const tree = parser.parse(methodBody);

        // Helper: Check if a variable name is likely a password
        function isLikelyPassword(name: string): boolean {
            // Check against password keywords
            const containsPasswordKeyword = passwordKeywords.some(keyword => 
                new RegExp(`\\b${keyword}\\b`, 'i').test(name)
            );
            
            // Check against false positive contexts
            const isFalsePositiveContext = falsePositiveContexts.some(context => 
                name.toLowerCase().includes(context.toLowerCase())
            );
            
            return containsPasswordKeyword && !isFalsePositiveContext;
        }
        
        // Helper: Check if a string literal looks like a password
        function isLikelyPasswordString(value: string): boolean {
            // Clean up the string and remove quotes
            const cleanValue = value.replace(/['"]/g, '').trim();
            
            // Empty or very short strings are not passwords
            if (cleanValue.length < 3) return false;
            
            // Check if string contains typical password patterns
            const hasPasswordPattern = /^[A-Za-z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{6,}$/.test(cleanValue);
            const hasConnectionString = /password=|passwd=|pwd=|auth=|user id=|username=/i.test(cleanValue);
            
            // Skip strings that are clearly URLs without credentials
            if (/^https?:\/\/[^:@]+$/i.test(cleanValue)) return false;
            
            return hasPasswordPattern || hasConnectionString;
        }
        
        // Helper: Check if password is being handled securely
        function isSecurelyHandled(variableName: string): boolean {
            return secureHandledVariables.has(variableName) || functionContext.hasMemset;
        }

        // Helper: Format line number
        function formatLineInfo(node: Parser.SyntaxNode): string {
            // Tree-sitter positions are 0-indexed, so add 1 for human-readable line numbers
            return `line ${node.startPosition.row + 1}`;
        }

        function traverse(node: Parser.SyntaxNode) {
            // 🔍 Track secure handling functions
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                
                // Check for password hashing or encryption
                if (secureFunctions.some(fn => fnName.toLowerCase().includes(fn))) {
                    functionContext.hasHashCall = true;
                    
                    // Get the argument variable if it exists
                    const argList = node.child(1);
                    if (argList) {
                        const firstArg = argList.namedChildren[0];
                        if (firstArg && firstArg.type === 'identifier') {
                            secureHandledVariables.add(firstArg.text);
                        }
                    }
                }
                
                // Check for memset which might be clearing passwords
                if (fnName === 'memset') {
                    functionContext.hasMemset = true;
                    
                    // Get the variable being cleared
                    const argList = node.child(1);
                    if (argList && argList.namedChildren.length >= 3) {
                        const firstArg = argList.namedChildren[0];
                        const thirdArg = argList.namedChildren[2];
                        
                        // If memset with 0 or NULL, this is password clearing
                        if (firstArg && 
                            firstArg.type === 'identifier' && 
                            (thirdArg?.text === '0' || thirdArg?.text.toLowerCase() === 'null')) {
                            secureHandledVariables.add(firstArg.text);
                        }
                    }
                }
            }
            
            // 🔍 Variable declaration and initialization detection
            if (node.type === 'declaration') {
                const initDeclarators = node.namedChildren.filter(child => 
                    child.type === 'init_declarator'
                );
                
                for (const initDeclarator of initDeclarators) {
                    const declarator = initDeclarator.namedChildren.find(child => 
                        child.type.includes('declarator')
                    );
                    const valueNode = initDeclarator.namedChildren.find(child =>
                        /literal/i.test(child.type) || /string/i.test(child.type)
                    );
                    
                    if (declarator && valueNode) {
                        const variableName = declarator.text.replace(/^\*+/, '').trim();
                        const variableValue = valueNode.text;
                        
                        // Check if variable name suggests it's a password
                        if (isLikelyPassword(variableName)) {
                            passwordVariables.add(variableName);
                            
                            // Only warn if it's assigned a string literal value
                            if (valueNode.type.includes('string') && isLikelyPasswordString(variableValue)) {
                                issues.push(
                                    `Warning: Hardcoded password detected in variable "${variableName}" in method "${methodName}" at ${formatLineInfo(node)}. Avoid storing passwords in plaintext.`
                                );
                            }
                        }
                        
                        // Check for connection strings even if variable doesn't have password in its name
                        if (valueNode.type.includes('string') && 
                            /password=|passwd=|pwd=/i.test(variableValue)) {
                            connectionStrings.add(variableName);
                            issues.push(
                                `Warning: Connection string with embedded password detected in variable "${variableName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                            );
                        }
                    } else if (declarator) {
                        // Handle uninitialized variables that might be passwords
                        const variableName = declarator.text.replace(/^\*+/, '').trim();
                        if (isLikelyPassword(variableName)) {
                            passwordVariables.add(variableName);
                        }
                    }
                }
            }
            
            // 🔍 Detect struct fields that might contain passwords
            if (node.type === 'field_declaration') {
                const fieldNameNode = node.namedChildren.find(c =>
                    c.type === 'pointer_declarator' || c.type === 'identifier' || c.type.includes('declarator')
                );
                
                if (fieldNameNode) {
                    const fieldName = fieldNameNode.text.replace(/^\*+/, '').trim();
                    if (isLikelyPassword(fieldName)) {
                        passwordVariables.add(fieldName);
                        issues.push(
                            `Warning: Struct field "${fieldName}" may contain a password in method "${methodName}" at ${formatLineInfo(node)}. Consider secure alternatives.`
                        );
                    }
                }
            }
            
            // 🔍 Detect access to password fields in structs
            if (node.type === 'field_expression') {
                const objName = node.child(0)?.text || '';
                const fieldName = node.child(node.namedChildCount - 1)?.text || '';
                
                // Check if the field itself is a likely password
                if (isLikelyPassword(fieldName) || passwordVariables.has(fieldName)) {
                    issues.push(
                        `Warning: Access to potential password field "${objName}.${fieldName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                    );
                }
            }
            
            // 🔍 Array access with potential password
            if (node.type === 'subscript_expression') {
                const arrayName = node.child(0)?.text || '';
                if (passwordVariables.has(arrayName)) {
                    // Check if it's part of an assignment
                    const parent = node.parent;
                    if (parent?.type === 'assignment_expression' && parent.child(0) === node) {
                        // The password array is being written to, not as concerning
                    } else {
                        issues.push(
                            `Warning: Access to password array "${arrayName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                        );
                    }
                }
            }
            
            // 🔍 Assignment to password variables
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0);
                const rhs = node.child(2);
                
                if (lhs?.type === 'identifier') {
                    const variableName = lhs.text;
                    
                    // Check if LHS is a password variable
                    if (isLikelyPassword(variableName)) {
                        passwordVariables.add(variableName);
                        
                        // Check if RHS is a string literal
                        if (rhs?.type.includes('string') && isLikelyPasswordString(rhs.text)) {
                            issues.push(
                                `Warning: Hardcoded password assigned to "${variableName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                            );
                        }
                    }
                }
            }

            // 🔍 Enhanced logging/output detection
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const argList = node.child(1);
                
                // Check for password variables in risky functions
                if (argList) {
                    // Convert all arguments to an array for easier processing
                    const args = argList.namedChildren;
                    
                    // Check if any argument contains password variables
                    for (let i = 0; i < args.length; i++) {
                        const arg = args[i];
                        
                        // Check direct password variable usage
                        if (arg.type === 'identifier' && passwordVariables.has(arg.text)) {
                            const pwVar = arg.text;
                            
                            // Don't flag if it's being securely handled
                            if (!isSecurelyHandled(pwVar)) {
                                if (riskyWriteFunctions.includes(fnName)) {
                                    issues.push(
                                        `Warning: Password variable "${pwVar}" passed to output function "${fnName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                                    );
                                }
                                
                                if (riskyLogFunctions.includes(fnName)) {
                                    issues.push(
                                        `Warning: Password variable "${pwVar}" logged using "${fnName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                                    );
                                }
                                
                                if (fileOperations.includes(fnName)) {
                                    issues.push(
                                        `Warning: Password variable "${pwVar}" may be stored in a file via "${fnName}" in method "${methodName}" at ${formatLineInfo(node)}.`
                                    );
                                }
                            }
                        }
                        
                        // Check for format strings with passwords
                        if (arg.type.includes('string') && i === 0 && 
                            (fnName === 'printf' || fnName === 'fprintf')) {
                            // This is a format string, check if any password variable appears in later args
                            for (let j = i + 1; j < args.length; j++) {
                                const laterArg = args[j];
                                if (laterArg.type === 'identifier' && passwordVariables.has(laterArg.text)) {
                                    issues.push(
                                        `Warning: Password variable "${laterArg.text}" may be printed via format string in method "${methodName}" at ${formatLineInfo(node)}.`
                                    );
                                }
                            }
                        }
                        
                        // Check string literals that might contain hardcoded passwords 
                        if (arg.type.includes('string') && isLikelyPasswordString(arg.text)) {
                            // Check if string looks like a connection string or hardcoded password
                            if (/password=|passwd=|pwd=/i.test(arg.text)) {
                                issues.push(
                                    `Warning: Connection string with embedded password detected in method "${methodName}" at ${formatLineInfo(node)}.`
                                );
                            }
                        }
                    }
                }
            }

            // Continue traversing children
            node.namedChildren.forEach(traverse);
        }

        // Start the traversal
        traverse(tree.rootNode);
        
        // Final checks based on the function context - these don't have line numbers
        // since they're based on overall function analysis, not specific nodes
        passwordVariables.forEach(pwVar => {
            // Recommend secure handling for any remaining unhandled password vars
            if (!secureHandledVariables.has(pwVar) && !functionContext.hasMemset) {
                issues.push(
                    `Warning: Password variable "${pwVar}" in method "${methodName}" should be cleared from memory after use.`
                );
            }
        });
        
        return issues;
    }
}