import Parser from 'tree-sitter';
import C from 'tree-sitter-c';
import * as vscode from 'vscode';
import { SecurityCheck } from "../c/SecurityCheck";

let parser: Parser;

function initParser() {
    if (!parser) {
        parser = new Parser();
        parser.setLanguage(C as unknown as Parser.Language);
    }
}

function findInsecureRNGInsideLoops(code: string, loopFunctions: string[]): string[] {
    initParser();
    const tree = parser.parse(code);
    const insecureCalls: string[] = [];

    function visit(node: Parser.SyntaxNode) {
        if (
            node.type === 'for_statement' ||
            node.type === 'while_statement' ||
            node.type === 'do_statement'
        ) {
            const loopBody = node.namedChildren.find(child => child.type === 'compound_statement');
            if (loopBody) {
                function findCalls(n: Parser.SyntaxNode) {
                    if (n.type === 'function_definition') return; // skip nested functions
                    if (n.type === 'call_expression') {
                        const fnName = n.child(0)?.text || '';
                        if (loopFunctions.includes(fnName)) {
                            insecureCalls.push(fnName);
                        }
                    }
                    n.namedChildren.forEach(findCalls);
                }
                findCalls(loopBody);
            }
        }
        node.namedChildren.forEach(visit);
    }

    visit(tree.rootNode);
    return insecureCalls;
}

export class RandomNumberGenerationCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const config = vscode.workspace.getConfiguration('securityAnalysis');

        const secureRandomFunctions = config.get<string[]>('secureRandomFunctions', ['rand_s', 'rand_r', 'random_r', 'arc4random', 'getrandom', 'CryptGenRandom']);
        const secureSeeds = config.get<string[]>('secureSeeds', ['getrandom', 'CryptGenRandom']);
        const loopFunctions = config.get<string[]>('loopFunctions', ['rand', 'random', 'drand48', 'lrand48']);

        let match;

        // 🔍 Phase 1: Regex - Detect Insecure RNG Usage
        const insecureRandomPattern = new RegExp(`\\b(${loopFunctions.join('|')})\\s*\\(`, 'g');
        while ((match = insecureRandomPattern.exec(methodBody)) !== null) {
            issues.push(`Warning: Insecure random number generator "${match[1]}" detected in method "${methodName}". Use secure alternatives.`);
        }

        // 🔍 Phase 2: Detect Insecure Seeding
        const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;
        while ((match = randomSeedPattern.exec(methodBody)) !== null) {
            issues.push(`Warning: Using time(NULL) as a seed is insecure in method "${methodName}". Use a secure seed source.`);
        }

        // 🧠 Phase 3: AST - Detect RNG calls inside loops
        const callsInLoops = findInsecureRNGInsideLoops(methodBody, loopFunctions);
        if (callsInLoops.length > 0) {
            issues.push(`Warning: Insecure RNG used inside loop in "${methodName}": ${callsInLoops.join(', ')}`);
        }

        // 🔍 Phase 4: Context-aware analysis (still regex for now)
        const contextAnalysis = [
            {
                pattern: /\b(rand|random|drand48|lrand48)\b\s*\(\s*([^)]+)\s*\)/g,
                handler: (fn: string, args: string) => {
                    if (!secureRandomFunctions.includes(fn)) {
                        return `Insecure seed source "${args}" for ${fn}`;
                    }
                    return null;
                }
            },
            {
                pattern: /\b(srand|srand48|srandom)\s*\(\s*([^)]+)\s*\)/g,
                handler: (fn: string, seed: string) => {
                    if (!secureSeeds.includes(seed)) {
                        return `Insecure seed source "${seed}" for ${fn}`;
                    }
                    return null;
                }
            }
        ];

        contextAnalysis.forEach(({ pattern, handler }) => {
            while ((match = pattern.exec(methodBody)) !== null) {
                const msg = handler(match[1], match[2]);
                if (msg) {
                    issues.push(`Warning: ${msg} in "${methodName}"`);
                }
            }
        });

        return issues;
    }
}
