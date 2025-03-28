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

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const passwordKeywords = config.get<string[]>('passwordkeywords', [
            'pass', 'password', 'passwd', 'pwd', 'user_password', 'admin_password',
            'auth_pass', 'login_password', 'secure_password', 'db_password',
            'secret_key', 'passphrase', 'master_password'
        ]);

        const riskyWriteFunctions = ['fprintf', 'fwrite', 'fputs', 'write', 'printf', 'sprintf'];
        const riskyLogFunctions = ['log', 'console.log', 'System.out.println'];

        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            // 🔍 Password variable declaration detection
            if (node.type === 'declaration') {
                const initDeclarator = node.namedChildren.find(child => child.type === 'init_declarator');
                if (initDeclarator) {
                    const pointerDecl = initDeclarator.namedChildren.find(child => child.type.includes('declarator'));
                    const valueNode = initDeclarator.namedChildren.find(child =>
                        /literal/i.test(child.type) || /string/i.test(child.type)
                    );

                    if (pointerDecl && valueNode) {
                        const variableName = pointerDecl.text.replace('*', '').trim();
                        if (passwordKeywords.some(keyword =>
                            new RegExp(`\\b${keyword}\\b`, 'i').test(variableName))
                        ) {
                            passwordVariables.add(variableName);
                            issues.push(
                                `Warning: Potential password variable (${variableName}) assigned a value in method "${methodName}". Avoid hardcoded passwords.`
                            );
                        }
                    }
                }
            }
            if (node.type === 'field_declaration') {
                const fieldNameNode = node.namedChildren.find(c =>
                    c.type === 'pointer_declarator' || c.type === 'identifier' || c.type.includes('declarator')
                );
                 if (fieldNameNode) {
                    const fieldName = fieldNameNode.text;
                    if (passwordKeywords.some(keyword =>
                        new RegExp(`\\b${keyword}\\b`, 'i').test(fieldName))
                    ) {
                        passwordVariables.add(fieldName);
                        issues.push(
                            `Warning: Struct field "${fieldName}" may contain a password in method "${methodName}". Avoid hardcoding sensitive data.`
                        );
                    }
                }
            }
            
            
            if (node.type === 'field_expression') {
                const fieldName = node.child(node.namedChildCount - 1)?.text || '';
                if (passwordVariables.has(fieldName)) {
                    issues.push(
                        `Warning: Access to potential password field "${fieldName}" in method "${methodName}". Avoid exposing sensitive data.`
                    );
                }
            }
            

            // 🔍 Logging/output detection
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const argList = node.child(1);

                if (argList) {
                    const argsText = argList.text;
                    passwordVariables.forEach(pwVar => {
                        if (argsText.includes(pwVar)) {
                            if (riskyWriteFunctions.includes(fnName)) {
                                issues.push(
                                    `Warning: Password variable "${pwVar}" passed to output function "${fnName}" in method "${methodName}".`
                                );
                            }
                            if (riskyLogFunctions.includes(fnName)) {
                                issues.push(
                                    `Warning: Password variable "${pwVar}" logged using "${fnName}" in method "${methodName}".`
                                );
                            }
                        }
                    });
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);
        return issues;
    }
}
