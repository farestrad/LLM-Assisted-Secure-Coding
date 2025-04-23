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

export class RandomNumberGenerationCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const config = vscode.workspace.getConfiguration('securityAnalysis');

        const secureRandomFunctions = config.get<string[]>('secureRandomFunctions', [
            'rand_s', 'rand_r', 'random_r', 'arc4random', 'getrandom', 
            'CryptGenRandom', 'RAND_bytes', 'RAND_pseudo_bytes'
        ]);
        
        const secureSeeds = config.get<string[]>('secureSeeds', [
            'getrandom', 'CryptGenRandom', '/dev/urandom', '/dev/random', 
            'RAND_seed', 'RAND_add'
        ]);
        
        const insecureRandomFunctions = config.get<string[]>('insecureRandomFunctions', [
            'rand', 'random', 'drand48', 'lrand48', 'mrand48', 'jrand48'
        ]);

        const seedFunctions = config.get<string[]>('seedFunctions', [
            'srand', 'srandom', 'srand48', 'seed48'
        ]);

        // Track functions found in code
        const foundRandomFunctions = new Map<string, {line: number, isSecure: boolean}>();
        const foundSeedFunctions = new Map<string, {line: number, seedSource: string, isSecure: boolean}>();
        const rngCallsInLoops = new Map<string, number[]>(); // function -> array of line numbers
        const rngFunctionsWithoutSeed = new Set<string>();
        const validatedSeedSources = new Set<string>();
        const reusedSeeds = new Map<string, number[]>(); // seed source -> array of use line numbers
        
        // Track variable values for static analysis
        const variableValues = new Map<string, {value: any, line: number}>();
        
        initParser();
        const tree = parser.parse(methodBody);

        // Helper function to get line number
        function getLineNumber(node: Parser.SyntaxNode): number {
            return node.startPosition.row + 1;
        }
        
        // Track RNG function calls, inside/outside loops
        function traverse(node: Parser.SyntaxNode, insideLoop: boolean = false) {
            // Check for loops and update insideLoop state
            const isLoopNode = node.type === 'for_statement' || 
                               node.type === 'while_statement' || 
                               node.type === 'do_statement';
            
            // Check for conditionals containing validations
            if (node.type === 'if_statement') {
                const condition = node.childForFieldName('condition');
                
                if (condition) {
                    // Extract variables being validated
                    condition.descendantsOfType('identifier').forEach(id => {
                        // Variables used in conditionals might be validated
                        validatedSeedSources.add(id.text);
                    });
                }
            }
            
            // Check for variable assignments (to track values for static analysis)
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const right = node.child(2);
                
                if (left?.type === 'identifier' && right) {
                    const varName = left.text;
                    
                    // Try to determine the value statically if possible
                    if (right.type === 'number_literal') {
                        variableValues.set(varName, {
                            value: parseInt(right.text),
                            line: getLineNumber(node)
                        });
                    } else if (right.type === 'call_expression') {
                        const fnName = right.child(0)?.text;
                        if (fnName === 'time' && right.child(1)?.text.includes('NULL')) {
                            // Detect time(NULL) assignments
                            variableValues.set(varName, {
                                value: 'time(NULL)',
                                line: getLineNumber(node)
                            });
                        }
                    }
                }
            }
            
            // Check for function calls
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const fnLine = getLineNumber(node);
                const args = node.child(1); // argument list
                const argText = args?.text || '';
                
                // Check for random number generator functions
                if (insecureRandomFunctions.includes(fnName)) {
                    foundRandomFunctions.set(fnName, {
                        line: fnLine, 
                        isSecure: false
                    });
                    
                    // Record if inside a loop
                    if (insideLoop) {
                        if (rngCallsInLoops.has(fnName)) {
                            rngCallsInLoops.get(fnName)?.push(fnLine);
                        } else {
                            rngCallsInLoops.set(fnName, [fnLine]);
                        }
                    }
                    
                    // Check if appropriate seed function was called
                    if (!foundSeedFunctions.has('srand') && !foundSeedFunctions.has('srandom')) {
                        rngFunctionsWithoutSeed.add(fnName);
                    }
                } else if (secureRandomFunctions.includes(fnName)) {
                    foundRandomFunctions.set(fnName, {
                        line: fnLine, 
                        isSecure: true
                    });
                }
                
                // Check seed functions
                if (seedFunctions.includes(fnName)) {
                    let seedSource = '';
                    let isSecure = false;
                    
                    // Extract the seed source from args
                    if (args && args.namedChildCount > 0) {
                        const seedArg = args.namedChild(0);
                        seedSource = seedArg?.text || '';
                        
                        // Check if it's time(NULL)
                        if (seedSource.includes('time') && seedSource.includes('NULL')) {
                            isSecure = false;
                        } 
                        // Check if it's a secure seed source
                        else if (secureSeeds.some(s => seedSource.includes(s))) {
                            isSecure = true;
                        }
                        // Check if it's a validated variable
                        else if (validatedSeedSources.has(seedSource)) {
                            isSecure = true;
                        }
                        
                        // Record seed function use
                        foundSeedFunctions.set(fnName, {
                            line: fnLine, 
                            seedSource, 
                            isSecure
                        });
                        
                        // Track reused seeds
                        if (variableValues.has(seedSource)) {
                            if (reusedSeeds.has(seedSource)) {
                                reusedSeeds.get(seedSource)?.push(fnLine);
                            } else {
                                reusedSeeds.set(seedSource, [fnLine]);
                            }
                        }
                    }
                }
            }
            
            // Recursively traverse children with updated context
            node.namedChildren.forEach(child => {
                traverse(child, insideLoop || isLoopNode);
            });
        }
        
        // Start traversal of AST
        traverse(tree.rootNode);
        
        // 🔍 Phase 1: Check for insecure RNG functions
        for (const [fnName, details] of foundRandomFunctions) {
            if (!details.isSecure) {
                issues.push(
                    `Warning: Insecure random number generator "${fnName}" detected in method "${methodName}" at line ${details.line}. Use secure alternatives like getrandom(), RAND_bytes(), or arc4random().`
                );
            }
        }
        
        // 🔍 Phase 2: Check for insecure seeding practices
        for (const [fnName, details] of foundSeedFunctions) {
            if (!details.isSecure) {
                if (details.seedSource.includes('time') && details.seedSource.includes('NULL')) {
                    issues.push(
                        `Warning: Using time(NULL) as a seed is insecure in method "${methodName}" at line ${details.line}. Time-based seeds are predictable. Use a cryptographically secure seed source.`
                    );
                } else if (details.seedSource.match(/^\d+$/)) {
                    // Constant/hardcoded seed
                    issues.push(
                        `Warning: Using constant value (${details.seedSource}) as seed in "${fnName}" at line ${details.line} in method "${methodName}". Constant seeds lead to predictable sequences.`
                    );
                } else if (!details.seedSource || details.seedSource === '0') {
                    issues.push(
                        `Warning: Calling ${fnName} with ${details.seedSource || 'empty'} seed at line ${details.line} in method "${methodName}". Seed should be cryptographically secure.`
                    );
                }
            }
        }
        
        // 🔍 Phase 3: Check for RNG used inside loops
        for (const [fnName, lines] of rngCallsInLoops) {
            issues.push(
                `Warning: Insecure RNG "${fnName}" used inside loop at line(s) ${lines.join(', ')} in method "${methodName}". This may produce correlated random numbers. Consider moving the RNG call outside the loop.`
            );
        }
        
        // 🔍 Phase 4: Check for RNG used without seeding
        for (const fnName of rngFunctionsWithoutSeed) {
            issues.push(
                `Warning: Random number generator "${fnName}" used without proper seeding in method "${methodName}". This may lead to predictable sequences.`
            );
        }
        
        // 🔍 Phase 5: Check for reused seeds
        for (const [seedVar, lines] of reusedSeeds) {
            if (lines.length > 1) {
                issues.push(
                    `Warning: Seed variable "${seedVar}" reused for multiple RNG initializations at lines ${lines.join(', ')} in method "${methodName}". Each RNG should have a unique seed.`
                );
            }
        }
        
        // 🔍 Phase 6: Additional regex pattern checks for common issues
        const patterns = [
            {
                regex: /\b(rand|random|drand48)\s*\(\s*\)\s*\%\s*(\d+)/g,
                message: (fn: string, modulo: string) => `Warning: Modulo bias when using "${fn}() % ${modulo}" detected in method "${methodName}". This reduces randomness quality. Use a secure method to generate bounded random numbers.`
            },
            {
                regex: /\b(rand|random|drand48)\s*\(\s*\)\s*\&\s*0x[0-9a-fA-F]+/g,
                message: (fn: string, mask: string) => `Warning: Bit masking operation "${fn}() & ${mask}" may reduce randomness quality in method "${methodName}".`
            },
            {
                regex: /for\s*\([^;]*;\s*[^;]*;\s*[^)]*\)\s*\{[^}]*\b(rand|random|drand48)\s*\(/g,
                message: (fn: string) => `Warning: Random number generator "${fn}" called inside loop body in method "${methodName}". This pattern may reduce randomness quality.`
            }
        ];
        
        patterns.forEach(pattern => {
            let match;
            while ((match = pattern.regex.exec(methodBody)) !== null) {
                issues.push(pattern.message(match[1], match[2] || ''));
            }
        });

        return issues;
    }
}