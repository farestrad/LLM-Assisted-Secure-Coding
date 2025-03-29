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
        const mallocChecked = new Set<string>();
        const reallocTargets = new Map<string, string>();

        const freedPtrs = new Map<string, number>(); // pointer -> free() startIndex
        const tree = (() => { initParser(); return parser.parse(methodBody); })();

        function traverse(node: Parser.SyntaxNode) {
            // Track heap allocations
            if (node.type === 'assignment_expression') {
                const lhsNode = node.child(0);
                const lhsIdent = lhsNode?.descendantsOfType('identifier')?.[0]?.text;
                
                const rhs = node.child(2);
                const fn = rhs?.child(0)?.text;
                const args = rhs?.child(1)?.namedChildren;

                if (
                    lhsIdent && rhs?.type === 'call_expression' &&
                    ['malloc', 'calloc', 'realloc'].includes(fn || '')
                ) {
                    const sizeExpr =
                        fn === 'calloc' && args?.length === 2
                            ? `${args[0].text} * ${args[1].text}`
                            : args?.[0]?.text || 'unknown';

                            if (lhsIdent) {
                                heapAllocations.set(lhsIdent, { sizeExpr, node });
                            }
                            

                    if (fn === 'realloc' && args?.length === 2) {
                        const ptr = args[0]?.text;
                        const newSize = args[1]?.text;
                        if (ptr && newSize) {
                            reallocTargets.set(ptr, newSize);
                        }
                    }
                }
            }

            // Validation checks
            if (node.type === 'if_statement' || node.type === 'while_statement') {
                const cond = node.childForFieldName('condition');
                cond?.descendantsOfType('identifier').forEach(id => {
                    validationChecks.add(id.text);
                    mallocChecked.add(id.text);
                });
            }

            // Track arithmetic
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0)?.text;
                const rhs = node.child(2);
                if (lhs && rhs?.type === 'binary_expression') {
                    arithmeticVars.add(lhs);
                }
            }

            // Free tracking with AST position
            if (node.type === 'call_expression' && node.child(0)?.text === 'free') {
                const freed = node.child(1)?.descendantsOfType('identifier')?.[0]?.text;

                if (freed) {
                    freedPtrs.set(freed, node.startIndex); // track position of `free(ptr)`
                }
            }

            // Memcpy etc.
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

        function findUseAfterFree(node: Parser.SyntaxNode, freedAt: Map<string, number>) {
            node.namedChildren.forEach(child => {
                findUseAfterFree(child, freedAt);
            });
        
            // Only warn if access is OUTSIDE or AFTER the block that freed it
            for (const [varName, freeStart] of freedPtrs.entries()) {
                if (node.startIndex > freeStart) {
                    const isUsage =
                        (node.type === 'identifier' && node.text === varName) ||
                        (node.type === 'subscript_expression' && node.namedChild(0)?.text === varName) ||
                        (node.type === 'unary_expression' && node.text.startsWith('*') && node.namedChild(0)?.text === varName);
        
                    if (isUsage) {
                        // Make sure the node isn't INSIDE the same block as the free() call
                        const freeNode = findNodeByStartIndex(tree.rootNode, freeStart);
                        const freeParentBlock = getEnclosingBlock(freeNode);
                        const usageBlock = getEnclosingBlock(node);
        
                        if (freeParentBlock !== usageBlock) {
                            issues.push(`Warning: Use-after-free — "${varName}" accessed after being freed in "${methodName}"`);
                        }
                    }
                }
            }
        }
        
        // Helpers
        function findNodeByStartIndex(root: Parser.SyntaxNode, startIndex: number): Parser.SyntaxNode | null {
            if (root.startIndex === startIndex) return root;
            for (const child of root.namedChildren) {
                const found = findNodeByStartIndex(child, startIndex);
                if (found) return found;
            }
            return null;
        }
        
        function getEnclosingBlock(node: Parser.SyntaxNode | null): Parser.SyntaxNode | null {
            while (node && node.type !== 'compound_statement') {
                node = node.parent;
            }
            return node;
        }
        

        findUseAfterFree(tree.rootNode, freedPtrs);


        // 🚨 Detect missing frees (memory leaks)
        for (const varName of heapAllocations.keys()) {
            if (!freedPtrs.has(varName)) {
                issues.push(`Warning: Heap-allocated variable "${varName}" in "${methodName}" is never freed (possible memory leak).`);
            }
        }


        // Final allocation checks
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

        for (const [ptr, sizeExpr] of reallocTargets.entries()) {
            if (!isSizeValidated(sizeExpr)) {
                issues.push(`Warning: realloc called on "${ptr}" with unvalidated size "${sizeExpr}" in "${methodName}"`);
            }

            if (isPotentialIntegerOverflow(sizeExpr)) {
                issues.push(`Warning: realloc called on "${ptr}" with potentially overflowing size in "${methodName}"`);
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
            return eval(expr.replace(/[^\d\+\-\*\/\(\)]/g, '')); // sanitized eval
        }
    }
}
