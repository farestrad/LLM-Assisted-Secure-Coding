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

// 🔧 Input-specific sanitization checker
function isSanitized(input: string, methodBody: string): boolean {
    const sanitizers = [
        'realpath',
        'basename',
        'dirname',
        'escapeshellarg',
        'escapeshellcmd',
        'htmlspecialchars',
        'htmlentities',
        'preg_replace'
    ];

    const sanitized = sanitizers.some(fn => {
        // Matches: input = fn(...)
        const pattern = new RegExp(`\\b${input}\\b\\s*=\\s*${fn}\\s*\\(`);
        return pattern.test(methodBody);
    });

    console.log(`Checking if "${input}" is sanitized: ${sanitized}`);
    return sanitized;
}


export class PathTraversalCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const riskyPaths = new Set<string>();
        const riskyFunctionCalls = new Set<string>();
        const unsanitizedInputs = new Set<string>();
        let match;

        // 🔧 Get patterns and escape them for regex use
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const rawPatterns = config.get<string[]>('pathTraversalPatterns', ['../', '~/', '\\..\\']);
        const pathTraversalPatterns = rawPatterns.map(escapeRegex);

        const riskyFunctions = config.get<string[]>('riskyFunctions', ['fopen', 'readfile', 'writefile', 'unlink', 'rename']);
        const fileOperations = config.get<string[]>('fileOperations', ['open', 'read', 'write', 'fread', 'fwrite', 'unlink', 'rename']);

        // 🔹 Phase 1: Regex Path Pattern Matching
        const pathTraversalPattern = new RegExp(`(${pathTraversalPatterns.join('|')})`, 'g');
        while ((match = pathTraversalPattern.exec(methodBody)) !== null) {
            const path = match[1];
            riskyPaths.add(path);
            issues.push(
                `Warning: Potential Path Traversal pattern "${path}" detected in method "${methodName}". Avoid using relative paths with user input.`
            );
        }


        // 🔹 Phase 2: AST-Based Function Call Analysis
        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            if (node.type === 'call_expression') {
                const fnNode = node.child(0);
                const argNode = node.child(1); // argument list
                const fnName = fnNode?.text || '';
                const argsText = argNode?.text || '';
            
                // Extract first argument only
                const rawArgs = argsText.replace(/^\((.*)\)$/, '$1'); // remove outer ()
                const args = rawArgs.split(',').map(a => a.trim());
                const firstArg = args[0];

                if ((riskyFunctions.includes(fnName) || fileOperations.includes(fnName)) && firstArg) {
                    const isTraversal = rawPatterns.some(p => firstArg.includes(p));
                    const isSafe = isSanitized(firstArg, methodBody);
                
                    if (!isSafe) {
                        riskyFunctionCalls.add(fnName);
                        issues.push(
                            `Warning: Path traversal risk — argument "${firstArg}" is passed to sensitive function "${fnName}" in method "${methodName}"`
                        );
                    }
                
                    if (!isSafe) {
                        unsanitizedInputs.add(firstArg);
                        issues.push(
                           `Warning: Unsanitized file path "${firstArg}" used as argument to "${fnName}" in method "${methodName}". Sanitize or validate before use.`
                        );
                    }
                }
                
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

        // 🔹 Phase 3: Context-aware Regex Checks (exec, include, etc.)
        const contextChecks = [
            {
                pattern: /\b(exec|system|popen)\s*\(\s*([^)]+)\s*\)/g,
                handler: (fn: string, arg: string) => {
                    // Always warn on unsanitized user input, regardless of content
                    if (!isSanitized(arg, methodBody)) {
                        return `Untrusted input "${arg}" passed to command execution function "${fn}" in method "${methodName}". This may enable path traversal or code execution.`;
                    }
                    return null;
                }

            },
            {
                pattern: /\b(include|require)\s*\(\s*([^)]+)\s*\)/g,
                handler: (fn: string, arg: string) => {
                    if (!isSanitized(arg, methodBody) && rawPatterns.some(p => arg.includes(p))) {
                        return `Untrusted input "${arg}" passed to "${fn}" in method "${methodName}". This may expose the application to file inclusion or path traversal attacks.`;
                    }
                    return null;
                }
            }
        ];

        contextChecks.forEach(({ pattern, handler }) => {
            while ((match = pattern.exec(methodBody)) !== null) {
                const msg = handler(match[1], match[2]);
                if (msg) issues.push(`Warning: ${msg}`);
            }
        });

        return issues;
    }
}
