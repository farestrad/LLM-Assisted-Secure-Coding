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

//  Unique identifier for AST nodes
function nodeKey(node: Parser.SyntaxNode): string {
    return `${node.type}-${node.startPosition.row}:${node.startPosition.column}`;
}

//  Extract variables from loop condition
function extractVariablesFromCondition(condition: string): string[] {
    const matches = Array.from(condition.matchAll(/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g));
    return matches.map(m => m[1]);
}

// Find modified variables in loop body
function loopModifiesVariables(loopBody: Parser.SyntaxNode | null | undefined, vars: Set<string>): Set<string> {
    const modified = new Set<string>();
    if (!loopBody) return modified;

    function check(node: Parser.SyntaxNode) {
        // ++i / i++
        if (node.type === 'update_expression') {
            const varName = node.child(0)?.text;
            if (varName && vars.has(varName)) {
                modified.add(varName);
            }
        }

        // i = ...
     if (node.type === 'assignment_expression') {
            const varName = node.child(0)?.text;
            if (varName && vars.has(varName)) {
                modified.add(varName);
            }
        }

        // i += n
        if (node.type === 'augmented_assignment_expression') {
            const varName = node.child(0)?.text;
            if (varName && vars.has(varName)) {
                modified.add(varName);
            }
        }

        node.namedChildren.forEach(check);
    }

    check(loopBody);
    return modified;
}

//  Extract increment vars from `for` loop header
function extractForIncrements(node: Parser.SyntaxNode): Set<string> {
    const incVars = new Set<string>();
    const updateNode = node.childForFieldName('update');
    if (!updateNode) return incVars;

    function collectIdentifiers(n: Parser.SyntaxNode) {
        if (n.type === 'identifier') {
            incVars.add(n.text);
        }
        n.namedChildren.forEach(collectIdentifiers);
    }

    collectIdentifiers(updateNode);
    return incVars;
}

export class InfiniteLoopCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const flaggedLoops = new Set<string>();

        initParser();
        const tree = parser.parse(methodBody);

        function traverse(
            node: Parser.SyntaxNode,
            inheritedModifiedVars: Set<string> = new Set()
        ) {
            if (
                node.type === 'for_statement' ||
                node.type === 'while_statement' ||
                node.type === 'do_statement'
            ) {
                const key = nodeKey(node);
                if (!flaggedLoops.has(key)) {
                    let conditionNode: Parser.SyntaxNode | null = null;
                    if (node.type === 'for_statement' || node.type === 'while_statement') {
                        conditionNode = node.childForFieldName('condition') || node.childForFieldName('parenthesized_expression');
                    } else if (node.type === 'do_statement') {
                        conditionNode = node.childForFieldName('condition'); // this is where 'while (1)' is stored
                    }

                    let conditionText = '';
                    if (conditionNode) {
                        const literal = conditionNode.namedChildren.find(child =>
                            ['number_literal', 'identifier'].includes(child.type)
                        );
                        conditionText = literal?.text.trim() || conditionNode.text.trim();
                    }

                    const loopVars = new Set(extractVariablesFromCondition(conditionText));
            
                    //  Add for-increment check if for_statement
                    const headerModified =
                        node.type === 'for_statement'
                            ? extractForIncrements(node)
                            : new Set<string>();
            
                    //  Loop body
                    const body = node.childForFieldName('body');
                    const bodyModified = loopModifiesVariables(body, loopVars);
            
                    const totalModified = new Set([
                        ...inheritedModifiedVars,
                        ...bodyModified,
                        ...headerModified
                    ]);
            
                    // 🔍 Detect infinite condition
                    const isInfinite =
                        conditionText === '' ||
                        conditionText === '1' ||
                        conditionText.toLowerCase() === 'true';

            
                    if (isInfinite) {
                        issues.push(
                            `Warning: Potential infinite '${node.type.replace('_statement', '')}' loop in method "${methodName}" at line ${node.startPosition.row + 1}. No termination condition detected.`
                        );
                    } else {
                        const unmodifiedVars = [...loopVars].filter(v => !totalModified.has(v));
                        if (unmodifiedVars.length > 0) {
                            issues.push(
                                `Warning: Loop variable(s) [${unmodifiedVars.join(', ')}] not modified in method "${methodName}" at line ${node.startPosition.row + 1}. May result in an infinite loop.`
                            );
                        }
                    }
            
                    flaggedLoops.add(key);
            
                    // Recurse
                    const inherited = new Set([
                        ...inheritedModifiedVars,
                        ...bodyModified,
                        ...headerModified
                    ]);
                    node.namedChildren.forEach(child => traverse(child, inherited));
                    return;
                }
            }
            

            //  Detect large memory allocations
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const args = node.child(1)?.text || '';

                if (/malloc|calloc|realloc/.test(fnName)) {
                    const sizeMatches = args.match(/\d+/g);
                    if (sizeMatches) {
                        const sizeValues = sizeMatches.map(n => parseInt(n, 10));
                        const total = sizeValues.reduce((sum, v) => sum * v, 1);
                        if (total > 1024 * 1024) {
                            issues.push(
                                `Warning: Excessive memory allocation (${total} bytes) using "${fnName}" in method "${methodName}".`
                            );
                        }
                    }
                }
            }

            node.namedChildren.forEach(child => traverse(child, inheritedModifiedVars));
        }

        traverse(tree.rootNode);
        return issues;
    }
}


