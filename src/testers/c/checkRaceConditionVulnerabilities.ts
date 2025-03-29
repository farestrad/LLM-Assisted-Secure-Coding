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
            'fopen', 'freopen', 'fwrite', 'fread', 'fprintf', 'fputs', 'fscanf',
            'open', 'write', 'close'
        ]);

        const metadataFunctions = ['access', 'stat', 'chmod', 'chown'];
        const fileLockFunctions = ['flock', 'lockf', 'fcntl']; // must be lowercase

        // 🔹 Phase 1: Parse with Tree-sitter
        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            if (node.type === 'call_expression') {
                const fnNode = node.child(0);
                const fnName = fnNode?.text || '';
                const normalizedFn = fnName.trim().toLowerCase();

                if (raceConditionKeywords.includes(normalizedFn)) {
                    fileAccessFunctions.add(normalizedFn);
                    issues.push(
                        `Warning: File access function "${fnName}" detected in method "${methodName}". Ensure proper file locking to prevent race conditions.`
                    );
                }

                if (metadataFunctions.includes(normalizedFn)) {
                    issues.push(
                        `Warning: File metadata operation "${fnName}" may cause race conditions in method "${methodName}". Avoid TOCTOU vulnerabilities.`
                    );
                }

                if (fileLockFunctions.includes(normalizedFn)) {
                    lockFunctionsFound.add(normalizedFn);
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

        // 🔹 Phase 2: Regex fallback (in case Tree-sitter misses a metadata call)
        const fallbackMetadataPattern = /\b(access|stat|chmod|chown)\s*\(/g;
        while ((match = fallbackMetadataPattern.exec(methodBody)) !== null) {
            const fn = match[1];
            if (!issues.some(msg => msg.includes(fn))) {
                issues.push(
                    `Potential race condition in file metadata operation "${fn}" in method "${methodName}". Avoid TOCTOU vulnerabilities.`
                );
            }
        }

        // 🔹 Phase 3: Locking enforcement
        if (fileAccessFunctions.size > 0 && lockFunctionsFound.size === 0) {
            issues.push(
                `Warning: File access detected without proper locking in method "${methodName}". Consider using locking functions like flock(), fcntl(), or lockf().`
            );
        }

        return issues;
    }
}
