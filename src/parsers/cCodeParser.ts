import * as vscode from 'vscode';
import Parser from 'tree-sitter';
import C from 'tree-sitter-c';
const outputChannel = vscode.window.createOutputChannel("C Parser"); // Create once and reuse

export class CCodeParser {
    private static parser: Parser;

    static initializeParser() {
        if (!this.parser) {
            this.parser = new Parser();
            this.parser.setLanguage(C as unknown as Parser.Language);
        }
    }

    static extractFunctions(code: string): {
        name: string;
        returnType: string;
        parameters: { type: string; name: string }[];
        lineNumber: number;
        functionBody: string;
        functionCalls: string[];
    }[] {
        this.initializeParser();
        const tree = this.parser.parse(code);
        const functions: {
            name: string;
            returnType: string;
            parameters: { type: string; name: string }[];
            lineNumber: number;
            functionBody: string;
            functionCalls: string[];
        }[] = [];

        function traverse(node: Parser.SyntaxNode) {
            if (node.type === 'function_definition') {
                const typeNode = node.childForFieldName('type');
                const declaratorNode = node.childForFieldName('declarator');
                const bodyNode = node.childForFieldName('body');

                if (typeNode && declaratorNode && bodyNode) {
                    const functionNameNode = declaratorNode.childForFieldName('declarator') || declaratorNode.child(0);
                    const parameterListNode = declaratorNode.childForFieldName('parameters');

                    const functionName = functionNameNode?.text || 'unknown';
                    const returnType = typeNode?.text || 'void';

                    const parameters = parameterListNode
                        ? parameterListNode.children
                            .filter((param) => param.type === 'parameter_declaration')
                            .map((param) => {
                                const type = param.childForFieldName('type')?.text || 'unknown';
                                const name = param.childForFieldName('declarator')?.text || `param_${Math.random().toString(36).substring(7)}`;
                                return { type, name };
                            })
                        : [];

                    const functionBody = bodyNode.text;

                    const functionCalls: string[] = [];
                    function findFunctionCalls(node: Parser.SyntaxNode) {
                        if (node.type === 'call_expression') {
                            functionCalls.push(node.child(0)?.text || 'unknown');
                        }
                        node.children.forEach(findFunctionCalls);
                    }
                    findFunctionCalls(bodyNode);

                    const lineNumber = node.startPosition.row + 1;

                    const extractedFunction = {
                        name: functionName,
                        returnType,
                        parameters,
                        lineNumber,
                        functionBody,
                        functionCalls,
                    };

                    functions.push(extractedFunction);

                    //  Persistently log all parsed functions
                    logParsedFunction(extractedFunction);
                }
            }

            node.children.forEach(traverse);
        }

        traverse(tree.rootNode);
        return functions;
    }
}

/**
 *  Ensures all parsed functions remain visible in the Output Console.
 */
function logParsedFunction(func: {
    name: string;
    returnType: string;
    parameters: { type: string; name: string }[];
    lineNumber: number;
    functionBody: string;
    functionCalls: string[];
}) {
    outputChannel.show(true); 
    outputChannel.appendLine("\n Parsed Function:");
    outputChannel.appendLine(`    Name: ${func.name}`);
    outputChannel.appendLine(`    Return Type: ${func.returnType}`);
    outputChannel.appendLine(`    Parameters: ${func.parameters.map(p => `${p.type} ${p.name}`).join(", ") || "None"}`);
    outputChannel.appendLine(`    Line Number: ${func.lineNumber}`);
    outputChannel.appendLine(`    Function Calls: ${func.functionCalls.join(", ") || "None"}`);
    outputChannel.appendLine(`    Function Body:\n${func.functionBody}`);
    outputChannel.appendLine("───────────────────────────────────────────────"); // Separator for readability
}
