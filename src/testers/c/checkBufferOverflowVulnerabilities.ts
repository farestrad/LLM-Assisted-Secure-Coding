import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { SecurityCheck } from "../c/SecurityCheck";
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';


export class BufferOverflowCheck implements SecurityCheck{
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const variables = new Map<string, number>(); //tracks buffer size 
        const validationChecks = new Set<string>(); // track wether ot not buffer was validated before being used
        const calledFunctions = new Set<string>(); // track function calls
        const validationFunctions = new Set<string>(); 

    // Get configuration from VSCode
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const stackThreshold = config.get<number>('stackBufferThreshold', 512);

    // Phase 1: Enhanced Buffer Declaration Tracking
    const declRegex = /(\b(?:char|int|long|unsigned|signed|[\w_]+)\s+)+\s*(\w+)\s*\[\s*(\d+)\s*\]/g;
    let match;
    while ((match = declRegex.exec(methodBody)) !== null) {
        variables.set(match[2], parseInt(match[3], 10));
    }

    // Phase 2: Advanced Validation Check Detection
    //if (strlen(buffer) < sizeof(buffer) ...)
    const validationRegex = /(?:\b(?:if|while|for)\s*\(|&&|\|\|).*\b(?:strlen|sizeof|_countof)\s*\(\s*(\w+)\s*\).*?(?:\)|;)/g;
    while ((match = validationRegex.exec(methodBody)) !== null) {
        validationChecks.add(match[1]);
    }

    // Phase 3: Inter-procedural Validation Tracking
    //identify function that return bool or int (i.e a validating function) ex bool isValid ( const char * input)...
    const valFuncRegex = /(?:bool|int)\s+(\w+)\s*\(.*\b(const char\s*\*|void\s*\*).*\)/g;
    while ((match = valFuncRegex.exec(methodBody)) !== null) {
        validationFunctions.add(match[1]);
    }

    // Phase 4: Function Call Tracking
    // detect recursion or unsafe function call
    const callRegex = /\b(\w+)\s*\(/g;
    while ((match = callRegex.exec(methodBody)) !== null) {
        calledFunctions.add(match[1]);
    }

    // Phase 5: Context-Aware Risky Function Analysis
    // use the before function to identify whats safe
    const functionChecks = [
        {
            pattern: /\b(strcpy|gets|sprintf)\s*\(\s*(\w+)\s*,/g,
            handler: (fn: string, buffer: string) => {
                if (!validationChecks.has(buffer) && !isValidatedByFunction(buffer)) {
                    return `Unvalidated ${fn} usage with "${buffer}"`;
                }
                return null;
            }
        },
        {
            pattern: /\bmalloc\s*\(\s*(\w+)\s*\)/g,
            handler: (_: string, sizeVar: string) => {
                if (!validationChecks.has(sizeVar)) {
                    return `Untrusted allocation size "${sizeVar}"`;
                }
                //return null; put back
            }
        },
        {
            pattern: /\b(memcpy|memmove)\s*\(\s*(\w+)\s*,\s*\w+,\s*([^)]+)\s*\)/g,
            handler: (fn: string, destBuffer: string, sizeExpr: string) => {
                const declaredSize = variables.get(destBuffer);
                const sizeValue = parseSizeExpression(sizeExpr);
                
                if (declaredSize && sizeValue && sizeValue > declaredSize) {
                    return `${fn} copying ${sizeValue} bytes into "${destBuffer}" (${declaredSize} bytes)`;
                }
                return null;
            }
        }
    ];

    functionChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2], match[3]);
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });

    // Phase 6: Recursive Function that uses buffer Analysis 
    /*
    How it works:
    Checks if the function calls itself.
    If true, lists all local buffers and warns about recursion risks.
    */
    if (calledFunctions.has(methodName)) {
        const localBuffers = Array.from(variables.keys()).join(', ');
        if (localBuffers) {
            issues.push(`Warning: Recursive function "${methodName}" with local buffers (${localBuffers})`);
        }
    }

    // Phase 7: Stack Allocation Analysis
    /*
    Why?
    Allocating large buffers on the stack can cause stack overflow vulnerabilities.
    */
    const largeBufferPattern = /\b(char|int|long)\s+(\w+)\s*\[\s*(\d+)\s*\]/g;
    while ((match = largeBufferPattern.exec(methodBody)) !== null) {
        const bufferSize = parseInt(match[3], 10);
        if (bufferSize > stackThreshold) {
            issues.push(`Warning: Large stack buffer "${match[2]}" (${bufferSize} bytes) in "${methodName}"`);
        }
    }

    // Phase 8: Pointer Arithmetic Checks
    const pointerRegex = /\b(\w+)\s*(\+|\-)=\s*\d+/g;
    while ((match = pointerRegex.exec(methodBody)) !== null) {
        if (variables.has(match[1])) {
            issues.push(`Warning: Pointer arithmetic on buffer "${match[1]}" in "${methodName}"`);
        }
    }

    // Phase 9: Array Index Validation
    const indexRegex = /\b(\w+)\s*\[\s*(\w+)\s*\]/g;
    while ((match = indexRegex.exec(methodBody)) !== null) {
        const [buffer, index] = [match[1], match[2]];
        if (!validationChecks.has(index)) {
            issues.push(`Warning: Unvalidated index "${index}" used with "${buffer}" in "${methodName}"`);
        }
    }

    // Phase 10: Memory Allocation Checks
    const allocationFunctions = ['malloc', 'calloc', 'realloc'];
    allocationFunctions.forEach((func) => {
        const allocationRegex = new RegExp(`\\b${func}\\s*\\(`, 'g');
        const checkedRegex = new RegExp(`if\\s*\\(\\s*${func}\\s*\\(`);

        while ((match = allocationRegex.exec(methodBody)) !== null) {
            if (!checkedRegex.test(methodBody)) {
                issues.push(`Warning: Unchecked return value of "${func}" in "${methodName}"`);
            }
        }
    });

    // Helper Functions
    function parseSizeExpression(expr: string): number | null {
        // Handle sizeof() expressions
        const sizeofMatch = expr.match(/sizeof\s*\(\s*(.+?)\s*\)/);

        //if (sizeofMatch) return variables.get(sizeofMatch[1]) || null; put back

        // Handle arithmetic expressions
        if (expr.includes('+') || expr.includes('*')) {
            try {
                return eval(expr.replace(/\b(\w+)\b/g, (_, v) => variables.get(v)?.toString() || '0'));
            } catch {
               // return null; put back
            }
        }

        // Handle numeric literals and variables
        return parseInt(expr, 10) || variables.get(expr) || null;
    }

    function isValidatedByFunction(buffer: string): boolean {
        return Array.from(validationFunctions).some(fn => 
            new RegExp(`\\b${fn}\\s*\\(\\s*${buffer}\\s*\\)`).test(methodBody)
        );
    }

    return issues;
}
}