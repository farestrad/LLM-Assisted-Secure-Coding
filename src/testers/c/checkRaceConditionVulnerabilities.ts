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
        const fileAccessFunctions = new Set<string>();
        const lockFunctionsFound = new Set<string>();
        let match;

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const raceConditionKeywords = config.get<string[]>('raceConditionKeywords', [
            'fopen', 'freopen', 'fwrite', 'fread', 'fclose', 'fprintf', 'fputs', 'fscanf'
        ]);
        const metadataFunctions = ['access', 'stat', 'chmod', 'chown'];
        const fileLockFunctions = ['flock', 'lockf', 'fcntl'];

        // 🔹 Phase 1: AST-based scan for file operations & locking
        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const args = node.child(1)?.text || '';

                if (raceConditionKeywords.includes(fnName)) {
                    fileAccessFunctions.add(fnName);
                    issues.push(`Warning: File access function "${fnName}" detected in method "${methodName}". Ensure proper file locking.`);
                }

                if (metadataFunctions.includes(fnName)) {
                    issues.push(`Warning: File metadata operation "${fnName}" may cause race conditions in method "${methodName}".`);
                }

                if (fileLockFunctions.includes(fnName)) {
                    lockFunctionsFound.add(fnName);
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

        // 🔹 Phase 2: Regex fallback for extra context (optional but still useful)
        const fallbackChecks = [
            {
                pattern: /\b(access|stat|chmod|chown)\s*\(/g,
                handler: (fn: string) =>
                    `Potential race condition in file metadata operation "${fn}" in method "${methodName}".`
            }
        ];

        fallbackChecks.forEach(({ pattern, handler }) => {
            while ((match = pattern.exec(methodBody)) !== null) {
                const fn = match[1];
                if (!issues.some(msg => msg.includes(fn))) {
                    issues.push(handler(fn));
                }
            }
        });

        // 🔹 Phase 3: Warn if locking is missing
        if (fileAccessFunctions.size > 0 && lockFunctionsFound.size === 0) {
            issues.push(`Warning: File access detected without proper locking in method "${methodName}". Consider using locking functions like flock(), fcntl(), or lockf().`);
        }

        return issues;
    }
}