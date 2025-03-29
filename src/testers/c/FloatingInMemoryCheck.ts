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

export class FloatingInMemoryCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        console.log(`[FloatingCheck] Checking method: ${methodName}`);
        const issues: string[] = [];
        const heapVars = new Set<string>();
        const usedVars = new Set<string>();
        const freedVars = new Set<string>();

        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            // Track malloc/calloc/realloc assignments
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0)?.descendantsOfType('identifier')[0]?.text;
                const rhs = node.child(2);

                let callNode = rhs;
                if (rhs?.type === 'cast_expression') {
                    callNode = rhs.namedChildren.find(n => n.type === 'call_expression') || rhs;
                }

                const fn = callNode?.child(0)?.text;
                if (['malloc', 'calloc', 'realloc'].includes(fn || '') && lhs) {
                    heapVars.add(lhs);
                }
            }

            // Track usage (buf[0], *buf, buf->field, etc.)
            if (
                (node.type === 'subscript_expression' && node.namedChild(0)?.type === 'identifier') ||
                (node.type === 'unary_expression' && node.text.startsWith('*')) ||
                (node.type === 'field_expression' && node.child(0)?.type === 'identifier')
            ) {
                const id = node.namedChild(0)?.text;
                if (id) usedVars.add(id);
            }

            // Track free(var)
            if (node.type === 'call_expression') {
                const fn = node.child(0)?.text;
                if (fn === 'free') {
                    const arg = node.child(1)?.descendantsOfType('identifier')[0]?.text;
                    if (arg) {
                        freedVars.add(arg);
                    }
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

        // Compare sets
        heapVars.forEach(varName => {
            if (usedVars.has(varName) && !freedVars.has(varName)) {
                issues.push(`Warning: Heap-allocated variable "${varName}" in "${methodName}" is used but never freed (floating in memory).`);
            }
        });

        return issues;
    }
}
