// CodeParser.ts
export class cCodeParser {
    /**
     * Extracts methods/functions from the given code.
     * @param code The raw C/C++ code as a string.
     * @returns Array of objects containing method name, parameters, and body.
     */
    static extractMethods(code: string): { name: string; parameters: string[]; body: string }[] {
        const methodPattern = /\b(\w+)\s+(\w+)\s*\(([^)]*)\)\s*{([\s\S]*?)}/g;
        const methods: { name: string; parameters: string[]; body: string }[] = [];
        let match;

        while ((match = methodPattern.exec(code)) !== null) {
            methods.push({
                name: match[2], // Function name
                parameters: match[3] ? match[3].split(',').map((p) => p.trim()) : [], // Parameters
                body: match[4], // Function body
            });
        }

        return methods;
    }
}




// import fs from 'fs';
// import Parser from 'tree-sitter';
// import C from 'tree-sitter-c';

// export class CCodeParser {
//     private static parser: Parser;

//     // Initialize Tree-sitter parser for C
//     static initializeParser() {
//         if (!this.parser) {
//             this.parser = new Parser();
//             this.parser.setLanguage(C as unknown as Parser.Language);
//         }
//     }

//     /**
//      * Extracts functions from C code using Tree-sitter.
//      * @param code - The raw C code as a string.
//      * @returns Array of objects containing function metadata.
//      */
//     static extractFunctions(code: string): {
//         name: string;
//         returnType: string;
//         parameters: { type: string; name: string }[];
//         lineNumber: number;
//         functionCalls: string[];
//     }[] {
//         this.initializeParser();
//         const tree = this.parser.parse(code);
//         const functions: {
//             name: string;
//             returnType: string;
//             parameters: { type: string; name: string }[];
//             lineNumber: number;
//             functionCalls: string[];
//         }[] = [];

//         function traverse(node: Parser.SyntaxNode) {
//             if (node.type === 'function_definition') {
//                 const typeNode = node.childForFieldName('type');
//                 const declaratorNode = node.childForFieldName('declarator');
//                 const bodyNode = node.childForFieldName('body');

//                 if (typeNode && declaratorNode && bodyNode) {
//                     const functionNameNode = declaratorNode.childForFieldName('declarator') || declaratorNode.child(0);
//                     const parameterListNode = declaratorNode.childForFieldName('parameters');

//                     const functionName = functionNameNode?.text || 'unknown';
//                     const returnType = typeNode?.text || 'void';

//                     // Extract parameter types
//                     const parameters = parameterListNode
//                         ? parameterListNode.children
//                               .filter((param) => param.type === 'parameter_declaration')
//                               .map((param) => {
//                                   const type = param.childForFieldName('type')?.text || 'unknown';
//                                   const name = param.childForFieldName('declarator')?.text || 'unnamed';
//                                   return { type, name };
//                               })
//                         : [];

//                     // Find function calls inside the function body
//                     const functionCalls: string[] = [];
//                     function findFunctionCalls(node: Parser.SyntaxNode) {
//                         if (node.type === 'call_expression') {
//                             const functionName = node.child(0)?.text || 'unknown';
//                             functionCalls.push(functionName);
//                         }
//                         node.children.forEach(findFunctionCalls);
//                     }
//                     findFunctionCalls(bodyNode);

//                     // Get the line number where the function is declared
//                     const lineNumber = node.startPosition.row + 1; // Tree-sitter uses 0-based indexing, so add 1

//                     functions.push({
//                         name: functionName,
//                         returnType,
//                         parameters,
//                         lineNumber,
//                         functionCalls,
//                     });
//                 }
//             }

//             // Recursively traverse children
//             node.children.forEach(traverse);
//         }

//         traverse(tree.rootNode);
//         return functions;
//     }
// }

// // ** Read from test.c file **
// const filePath = 'test.c';

// if (fs.existsSync(filePath)) {
//     const code = fs.readFileSync(filePath, 'utf8');
//     const parsedFunctions = CCodeParser.extractFunctions(code);
//     console.log(JSON.stringify(parsedFunctions, null, 2));
// } else {
//     console.error(`Error: File '${filePath}' not found.`);
// }
