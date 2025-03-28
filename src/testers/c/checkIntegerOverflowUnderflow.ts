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

export class IntegerFlowCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const MAX_INT = Number.MAX_SAFE_INTEGER;
        const MIN_INT = Number.MIN_SAFE_INTEGER;

        const symbolTable = new Map<string, number>(); // variable -> constant value

        initParser();
        const tree = parser.parse(methodBody);

        function resolveIdentifier(name: string): number | null {
            return symbolTable.has(name) ? symbolTable.get(name)! : null;
        }

        function evaluate(node: Parser.SyntaxNode): number | null {
            if (!node) return null;

            switch (node.type) {
                case 'number_literal':
                    return parseInt(node.text);
                case 'identifier':
                    return resolveIdentifier(node.text);
                case 'binary_expression': {
                    const left = evaluate(node.child(0)!);
                    const operator = node.child(1)?.text;
                    const right = evaluate(node.child(2)!);

                    if (left === null || right === null || !operator) return null;

                    try {
                        switch (operator) {
                            case '+': return left + right;
                            case '-': return left - right;
                            case '*': return left * right;
                            case '/': return right !== 0 ? left / right : null;
                            default: return null;
                        }
                    } catch {
                        return null;
                    }
                }
                default:
                    return null;
            }
        }

        function traverse(node: Parser.SyntaxNode) {
            // Handle variable declarations with initializers (e.g., int x = a + b;)
            if (node.type === 'declaration') {
                for (const child of node.namedChildren) {
                    if (child.type === 'init_declarator') {
                        const idNode = child.childForFieldName('declarator');
                        const valueNode = child.childForFieldName('value');

                        if (idNode?.type === 'identifier' && valueNode) {
                            const val = evaluate(valueNode);
                            if (val !== null) {
                                symbolTable.set(idNode.text, val);
                                if (val > MAX_INT || val < MIN_INT) {
                                    issues.push(
                                        `Warning: Integer overflow/underflow detected in method "${methodName}" during declaration of "${idNode.text}".`
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Handle assignment expressions (e.g., x = a + b;)
            if (node.type === 'assignment_expression') {
                const left = node.child(0);
                const right = node.child(2);

                if (left?.type === 'identifier' && right) {
                    const val = evaluate(right);
                    if (val !== null) {
                        symbolTable.set(left.text, val);
                        if (val > MAX_INT || val < MIN_INT) {
                            issues.push(
                                `Warning: Integer overflow/underflow detected in method "${methodName}" during assignment to "${left.text}".`
                            );
                        }
                    }
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);
        return issues;
    }
}

