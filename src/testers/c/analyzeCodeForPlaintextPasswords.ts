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
        const fileWriteOperations = new Set<string>();
        let match;

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const passwordKeywords = config.get<string[]>('passwordkeywords', [
            'pass', 'password', 'passwd', 'pwd', 'user_password', 'admin_password',
            'auth_pass', 'login_password', 'secure_password', 'db_password',
            'secret_key', 'passphrase', 'master_password'
        ]);

        const riskyWriteFunctions = ['fprintf', 'fwrite', 'fputs', 'write', 'printf', 'sprintf'];
        const riskyLogFunctions = ['log', 'console.log', 'System.out.println'];

        // 🔹 Phase 1: AST-based Password Variable Detection
        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            // Detect variable assignments (e.g., password = "abc123")
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const right = node.child(2);

                if (left && right) {
                    const variableName = left.text;
                    const value = right.text;

                    if (passwordKeywords.some(keyword => variableName.toLowerCase().includes(keyword))) {
                        passwordVariables.add(variableName);
                        issues.push(
                            `Warning: Potential password variable (${variableName}) assigned a value in method "${methodName}". Avoid hardcoded passwords.`
                        );
                    }
                }
            }

            // Detect risky output/log functions that might expose passwords
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

        // 🔹 Optional Fallback Regex-Based File Write Detection
        const fileWritePattern = /\b(fwrite|fprintf|write|ofstream|fputs)\s*\(/g;
        while ((match = fileWritePattern.exec(methodBody)) !== null) {
            const func = match[1];
            if (!fileWriteOperations.has(func)) {
                fileWriteOperations.add(func);
                issues.push(
                    `Warning: File write operation "${func}" detected in method "${methodName}". Ensure sensitive data is encrypted before writing to file.`
                );
            }
        }

        return issues;
    }
}
