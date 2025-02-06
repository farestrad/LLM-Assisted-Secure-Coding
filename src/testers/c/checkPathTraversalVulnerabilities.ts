import * as vscode from 'vscode';
import { promisify } from 'util';
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';

/**
 * Check for path traversal vulnerabilities in a method. (Minhyeok)
 */
export class PathTraversalCheck{
    check(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const riskyPaths = new Set<string>();
    const riskyFunctionCalls = new Set<string>();
    const unsanitizedInputs = new Set<string>();
    let match;

    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const pathTraversalPatterns = config.get<string[]>('pathTraversalPatterns', ['../', '~/', '\\..\\']);
    const riskyFunctions = config.get<string[]>('riskyFunctions', ['fopen', 'readfile', 'writefile', 'unlink', 'rename']);
    const fileOperations = config.get<string[]>('fileOperations', ['open', 'read', 'write', 'fread', 'fwrite', 'unlink', 'rename']);

    // Phase 1: Path Traversal Pattern Detection
    const pathTraversalPattern = new RegExp(`\\b(${pathTraversalPatterns.join('|')})`, 'g');
    while ((match = pathTraversalPattern.exec(methodBody)) !== null) {
        const path = match[1];
        riskyPaths.add(path);
        issues.push(
            `Warning: Potential Path Traversal vulnerability detected in method "${methodName}". Avoid using relative paths with user input.`
        );
    }
    
    // Phase 2: Risky Function Detection
    riskyFunctions.forEach((func: string) => {
        const funcPattern = new RegExp(`\\b${func}\\b\\s*\\(([^)]+)\\)`, 'g');
        while ((match = funcPattern.exec(methodBody)) !== null) {
            const argument = match[1].trim();
            riskyFunctionCalls.add(func);
            issues.push(
                `Warning: Path traversal vulnerability detected in function "${func}" in method "${methodName}" with argument "${argument}". Avoid using relative paths with user input.`
            );
        }
    });

    // Phase 3: Unsanitized Input Detection
    const usagePattern = new RegExp(`\\b(${fileOperations.join('|')})\\s*\\(([^,]+),?`, 'g');
    while ((match = usagePattern.exec(methodBody)) !== null) {
        const input = match[2].trim();
        unsanitizedInputs.add(input);
        issues.push(
            `Warning: Unsanitized input "${input}" detected in file operation in method "${methodName}". Ensure input is sanitized before use.`
        );
    }

    // Phase 4: Context-Aware Analysis
    const contextChecks = [{
        pattern: /\b(exec|system|popen)\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, arg: string) => {
            if (arg.includes('../') || arg.includes('"') || arg.includes('`')) {
                return `Potential path traversal vulnerability detected in function "${fn}" with argument "${arg}" in method "${methodName}". Avoid using relative paths with user input.`;
            }
            return null;
        }
    },
    {
        pattern: /\b(include|require)\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, arg: string) => {
            if (arg.includes('../') || arg.includes('"') || arg.includes('`')) {
                return `Potential path traversal vulnerability detected in function "${fn}" with argument "${arg}" in method "${methodName}". Avoid using relative paths with user input.`;
            }
            return null;
        }
    }];

    contextChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2]);
            if (msg) issues.push(`Warning: ${msg}`);
        }
    });

    // Helper function to check if input is sanitized in a method.
    function isSanitized(input: string, methodBody: string): boolean {
        // Check if the input is sanitized using common sanitization functions
        const sanitizationPatterns = [
            /realpath\s*\(/,
            /basename\s*\(/,
            /dirname\s*\(/,
            /escapeshellarg\s*\(/,
            /escapeshellcmd\s*\(/,
            /htmlspecialchars\s*\(/,
            /htmlentities\s*\(/,
            /preg_replace\s*\(/
        ];
        return sanitizationPatterns.some(pattern => pattern.test(methodBody));
    }

    // Check for path traversal patterns (e.g., "../") 
    // const pathTraversalPattern = /\.\.\/|~\/|\\\.\.\\/g;
    // if (pathTraversalPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Potential Path Traversal vulnerability detected in method "${methodName}". Avoid using relative paths with user input.`
    //     );
    // }

    // Check for risky functions that may lead to path traversal 
    // const riskyFunctions = ['fopen', 'readfile', 'writefile', 'unlink', 'rename'];
    // riskyFunctions.forEach((func) => {
    //     const regex = new RegExp(`\\b${func}\\b\\s*\\(([^)]+)\\)`, 'g');
    //     while ((match = regex.exec(methodBody)) !== null) {
    //         const argument = match[1].trim();
    //         if (argument.includes('../') || argument.includes('"') || argument.includes('`')) {
    //             issues.push(
    //                 `Warning: Path traversal vulnerability detected in function "${func}" in method "${methodName}" with argument "${argument}". Avoid using relative paths with user input.`
    //             );
    //         }
    //     }
    // });

    // Check for unsanitized input usage in file operations 
    // const usagePattern = /\b(open|read|write|fread|fwrite|unlink|rename)\s*\(([^,]+),?/g;
    
    // while ((match = usagePattern.exec(methodBody)) !== null) {
    //     const input = match[2].trim();
    //     if (!isSanitized(input, methodBody)) {
    //         issues.push(
    //             `Warning: Unsanitized input "${input}" detected in file operation in method "${methodName}". Ensure input is sanitized before use.`
    //         );
    //     }
    // }

    return issues;
    }
}
