import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { SecurityCheck } from "../c/SecurityCheck";
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';



/**
 * Check for insecure random number generation in a method. (Minhyeok)
 */
export class RandomNumberGenerationCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const insecureRandomFunctions = new Set<string>();
        const insecureSeeds = new Set<string>();
        const insecureLoops = new Set<string>();

    let match;

    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const secureRandomFunctions = config.get<string[]>('secureRandomFunctions', ['rand_s', 'rand_r', 'random_r', 'arc4random', 'getrandom', 'CryptGenRandom']);
    const secureSeeds = config.get<string[]>('secureSeeds', ['getrandom', 'CryptGenRandom']);
    const loopFunctions = config.get<string[]>('loopFunctions', ['rand', 'random', 'drand48', 'lrand48']);

    // Phase 1: Detect Insecure Random Functions
    const insecureRandomPattern = new RegExp(`\\b(${loopFunctions.join('|')})\\s*\\(`, 'g');
    while ((match = insecureRandomPattern.exec(methodBody)) !== null) {
        const func = match[1];
        insecureRandomFunctions.add(func);
        issues.push(`Warning: Insecure random number generator "${func}" detected in method "${methodName}". Use secure alternatives or libraries.`);
    }

    // Phase 2: Detect Insecure Seeding with time(NULL)
    const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;
    while ((match = randomSeedPattern.exec(methodBody)) !== null) {
        insecureSeeds.add(match[0]);
        issues.push(`Warning: Using time(NULL) as a seed is insecure in method "${methodName}". Use a more secure seed source.`);
    }

    //Phase 3: Detect Insecure RNG in Loops
    const loopPattern = new RegExp(`\\b(${loopFunctions.join('|')})\\s*\\(`, 'g');
    while ((match = loopPattern.exec(methodBody)) !== null) {
        insecureLoops.add(match[0]);
        issues.push(`Warning: Insecure RNG "${match[0]}" detected in a loop in method "${methodName}". Ensure unbiased and secure random number generation.`);
    }

    // Phase 4: Context-Aware Analysis
    const contextAnalysis = [
    {
        pattern: /\b(rand|random|drand48|lrand48)\b\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, args: string) => {
            if (!secureRandomFunctions.includes(fn)) {
                return `Insecure seed source "${args}" for ${fn}`;
            }
            return null; // Explicitly return null to indicate no issues
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
    }];

    // Phase 5: Context Analysis
    contextAnalysis.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2]);
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });
     
    // // Detect insecure random functions
    // const insecureRandomPattern = /\b(rand|srand|random|drand48|lrand48|rand_r|random_r|srandom|srandom_r)\b\s*\(/g;
    // if (insecureRandomPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Insecure random number generator detected in method "${methodName}". Consider using secure alternatives or libraries.`
    //     );
    // }

    // // Detect insecure seeding with time(NULL)
    // const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;

    // while ((match = randomSeedPattern.exec(methodBody)) !== null) {
    //     issues.push(
    //         `Warning: Using time(NULL) as a seed is insecure in method "${methodName}". Use a more secure seed source.`
    //     );
    // }

    // // Detect use of insecure RNG in loops
    // const loopPattern = /\b(rand|random|drand48|lrand48)\b.*?\bfor\s*\(/g;
    
    // while ((match = loopPattern.exec(methodBody)) !== null) {
    //     issues.push(
    //         `Warning: Insecure RNG '${match[1]}' detected in a loop in method "${methodName}". Ensure unbiased and secure random number generation.`
    //     );
    // }

    return issues;
    }
}
