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

export class HeapOverflowCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const heapAllocations = new Map<string, { sizeExpr: string, node: Parser.SyntaxNode }>();
        const validationChecks = new Set<string>();
        const arithmeticVars = new Set<string>();
        const freedVars = new Set<string>();
        const mallocChecked = new Set<string>();
        const reallocTargets = new Map<string, string>(); // var -> sizeExpr

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const tree = (() => { initParser(); return parser.parse(methodBody); })();

        function traverse(node: Parser.SyntaxNode) {
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0)?.text;
                const rhs = node.child(2);
                const fn = rhs?.child(0)?.text;
                const args = rhs?.child(1)?.namedChildren;

                if (
                    lhs && rhs?.type === 'call_expression' &&
                    ['malloc', 'calloc', 'realloc'].includes(fn || '')
                ) {
                    const sizeExpr =
                        fn === 'calloc' && args?.length === 2
                            ? `${args[0].text} * ${args[1].text}`
                            : args?.[0]?.text || 'unknown';

                    heapAllocations.set(lhs, { sizeExpr, node });

                    if (fn === 'realloc' && args?.length === 2) {
                        const ptr = args[0]?.text;
                        const newSize = args[1]?.text;
                        if (ptr && newSize) {
                            reallocTargets.set(ptr, newSize);
                        }
                    }
                }
            }

            if (node.type === 'if_statement' || node.type === 'while_statement') {
                const cond = node.childForFieldName('condition');
                if (cond) {
                    cond.descendantsOfType('identifier').forEach(id => {
                        validationChecks.add(id.text);
                        mallocChecked.add(id.text);
                    });
                }
            }

            if (node.type === 'assignment_expression') {
                const lhs = node.child(0)?.text;
                const rhs = node.child(2);
                if (lhs && rhs?.type === 'binary_expression') {
                    arithmeticVars.add(lhs);
                }
            }

            // Track free() calls
            if (node.type === 'call_expression' && node.child(0)?.text === 'free') {
                const freed = node.child(1)?.namedChildren?.[0]?.text;
                if (freed) {
                    freedVars.add(freed);
                }
            }

            // Memory ops (memcpy etc.)
            if (node.type === 'call_expression') {
                const fn = node.child(0)?.text || '';
                const args = node.child(1)?.namedChildren || [];

                const dest = args[0]?.text;
                const sizeExpr = args[2]?.text;

                if (
                    ['memcpy', 'memmove', 'snprintf', 'strncpy'].includes(fn) &&
                    dest && heapAllocations.has(dest)
                ) {
                    const { sizeExpr: allocExpr } = heapAllocations.get(dest)!;
                    if (!isSizeValidated(allocExpr)) {
                        issues.push(`Warning: Unvalidated ${fn} to heap-allocated "${dest}" in "${methodName}"`);
                    }

                    if (isPotentialOverflow(sizeExpr, allocExpr)) {
                        issues.push(`Warning: Possible overflow in ${fn} into "${dest}" in "${methodName}"`);
                    }
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

        // Final checks for heap allocations
        for (const [varName, { sizeExpr }] of heapAllocations.entries()) {
            if (!isSizeValidated(sizeExpr)) {
                issues.push(`Warning: Untrusted allocation size for "${varName}" (${sizeExpr}) in "${methodName}"`);
            }

            if (isPotentialIntegerOverflow(sizeExpr)) {
                issues.push(`Warning: Potential integer overflow in allocation size for "${varName}" in "${methodName}"`);
            }

            if (!mallocChecked.has(varName)) {
                issues.push(`Warning: Unchecked malloc/calloc result for "${varName}" in "${methodName}"`);
            }
        }

        // ⚠️ Validate realloc targets
        for (const [ptr, sizeExpr] of reallocTargets.entries()) {
            if (!isSizeValidated(sizeExpr)) {
                issues.push(`Warning: realloc called on "${ptr}" with unvalidated size "${sizeExpr}" in "${methodName}"`);
            }

            if (isPotentialIntegerOverflow(sizeExpr)) {
                issues.push(`Warning: realloc called on "${ptr}" with potentially overflowing size in "${methodName}"`);
            }
        }

        // ⚠️ Use-after-free detection
        for (const varName of freedVars) {
            if (heapAllocations.has(varName)) {
                issues.push(`Warning: Potential use-after-free of heap variable "${varName}" in "${methodName}"`);
            }
        }

        return issues;

        function isSizeValidated(expr: string): boolean {
            return expr.split(/\b[\+\-\*\/]\b/).some(token =>
                validationChecks.has(token.trim()) ||
                /^\d+$/.test(token.trim()) ||
                token.includes('sizeof')
            );
        }

        function isPotentialIntegerOverflow(expr: string): boolean {
            return expr.split(/\b[\+\-\*\/]\b/).some(token =>
                arithmeticVars.has(token.trim()) && !validationChecks.has(token.trim())
            );
        }

        function isPotentialOverflow(copyExpr: string | undefined, allocExpr: string): boolean {
            if (!copyExpr) return false;
            try {
                const allocVal = evalExpr(allocExpr);
                const copyVal = evalExpr(copyExpr);
                return copyVal > allocVal;
            } catch {
                return false;
            }
        }

        function evalExpr(expr: string): number {
            return eval(expr.replace(/[^\d\+\-\*\/\(\)]/g, '')); // sanitized
        }
    }
}
