import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';

/**
 * Check for heap overflow vulnerabilities in a method.
 */
export class HeapOverflowCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const heapAllocations = new Map<string, { size: string; line: number }>();
        const validationChecks = new Set<string>();
        const arithmeticOperations = new Set<string>();
        const freedVariables = new Set<string>();
        let lineNumber = 1

    // Phase 1: Track Heap Allocations and Reallocations
    const allocationRegex = /(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]+)\)/g;
    let match;
    while ((match = allocationRegex.exec(methodBody)) !== null) {
        const [varName, func, args] = [match[1], match[2], match[3]];
        const sizeExpr = func === 'calloc' ? args.split(',')[1] : args;

        heapAllocations.set(varName, {
            size: sizeExpr.trim(),
            line: lineNumber + countNewlines(methodBody.slice(0, match.index))
        });
    }

    // Phase 2: Detect Size Validation Patterns
    const validationRegex = /(?:if|while|assert)\s*\(.*\b(sizeof|strlen|_countof)\(([^)]+)\).*[<>=]/g;
    while ((match = validationRegex.exec(methodBody)) !== null) {
        validationChecks.add(match[2].trim());
    }

    // Phase 3: Analyze Size Calculations
    const arithmeticRegex = /(\w+)\s*=\s*(\w+)\s*([*+/-])\s*(\w+)/g;
    while ((match = arithmeticRegex.exec(methodBody)) !== null) {
        arithmeticOperations.add(match[1]);
        if (!validationChecks.has(match[2]) || !validationChecks.has(match[4])) {
            issues.push(`Warning: Unvalidated arithmetic operation (${match[0]}) in "${methodName}"`);
        }
    }

    // Phase 4: Analyze Memory Operations (Including Manual Buffer Copying)
    const memoryOperationChecks = [
        {
            pattern: /(memcpy|memmove|strcpy|strncpy|sprintf)\s*\(\s*(\w+)\s*,/g,
            handler: (fn: string, dest: string) => {
                const alloc = heapAllocations.get(dest);
                if (alloc && !isSizeValidated(alloc.size, validationChecks)) {
                    return `Unvalidated ${fn} to heap-allocated "${dest}"`;
                }
                return null;
            }
        },
        {
            pattern: /realloc\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\)/g,
            handler: (_: string, ptr: string, newSize: string) => {
                if (!isSizeValidated(newSize, validationChecks)) {
                    return `Unvalidated realloc of "${ptr}" with size "${newSize}"`;
                }
                return null;
            }
        },
        {
            pattern: /(\w+)\s*=\s*\w+\s*\+\s*\d+/g,
            handler: (varName: string) => {
                if (heapAllocations.has(varName) && !validationChecks.has(varName)) {
                    return `Unsafe pointer arithmetic on heap variable "${varName}"`;
                }
                return null;
            }
        }
    ];

    memoryOperationChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2], match[3] || '');
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });

    // Detect Manual Copying in Loops (Buffer Overflows)
    const loopCopyRegex = /\bfor\s*\(\s*[^;]+;\s*[^;]+;\s*[^)]+\s*\)\s*{[^}]*\b\w+\s*\[\s*\w+\s*\]\s*=/gs;
    while ((match = loopCopyRegex.exec(methodBody)) !== null) {
        issues.push(`Warning: Possible buffer overflow due to manual copying in loop in "${methodName}".`);
    }

    // Phase 5: Check Allocation Sizes
    heapAllocations.forEach((alloc, varName) => {
        if (!isSizeValidated(alloc.size, validationChecks)) {
            issues.push(`Warning: Untrusted allocation size for "${varName}" (${alloc.size}) in "${methodName}" at line ${alloc.line}`);
        }

        if (isPotentialIntegerOverflow(alloc.size, arithmeticOperations)) {
            issues.push(`Warning: Potential integer overflow in allocation size for "${varName}" (${alloc.size}) in "${methodName}"`);
        }
    });

    // Phase 6: Check Allocation Success (Improved)
    const uncheckedAllocRegex = /(\w+)\s*=\s*(malloc|calloc|realloc)\s*\([^)]+\)/g;
    while ((match = uncheckedAllocRegex.exec(methodBody)) !== null) {
        const varName = match[1];
        const func = match[2];

        // Look for an if-statement that checks if varName is NULL
        const validationPattern = new RegExp(`if\\s*\\(\\s*!?\\s*${varName}\\s*\\)`, 'g');
        if (!validationPattern.test(methodBody)) {
            issues.push(`Warning: Unchecked "${func}" result for "${varName}" in "${methodName}"`);
        }
    }

    // Phase 7: Detect Use-After-Free
    const freeRegex = /\bfree\s*\(\s*(\w+)\s*\)/g;
    while ((match = freeRegex.exec(methodBody)) !== null) {
        freedVariables.add(match[1]);
    }

    return issues;

    // Helper functions
    function countNewlines(str: string): number {
        return (str.match(/\n/g) || []).length;
    }

    function isSizeValidated(sizeExpr: string, validations: Set<string>): boolean {
        return sizeExpr.split(/\s*[+*/-]\s*/).some(part => 
            validations.has(part) || 
            /\d+/.test(part) || 
            part.startsWith('sizeof')
        );
    }

    function isPotentialIntegerOverflow(sizeExpr: string, arithmeticVars: Set<string>): boolean {
        return sizeExpr.split(/\s*[+*/-]\s*/).some(term => 
            arithmeticVars.has(term) || 
            (/\b\w+\b/.test(term) && !validationChecks.has(term))
        );
    }
}

}