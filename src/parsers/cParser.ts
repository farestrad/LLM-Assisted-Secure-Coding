// import Parser from 'tree-sitter';
// import C from 'tree-sitter-c';

// export async function parseCCode(code: string) {
//     const parser = new Parser();
//     parser.setLanguage(C as unknown as Parser.Language); 
//     const tree = parser.parse(code);

//     return extractFunctions(tree.rootNode);
// }


// function extractFunctions(node: any): { name: string; parameters: string; body: string }[] {
//     const methods: { name: string; parameters: string; body: string }[] = [];

//     if (node.type === 'function_definition') {
//         const name = node.childForFieldName('declarator')?.text || 'unknown';
//         const params = node.childForFieldName('parameters')?.text || '';
//         const body = node.childForFieldName('body')?.text || '';
//         methods.push({ name, parameters: params, body });
//     }

//     for (let child of node.children) {
//         methods.push(...extractFunctions(child));
//     }

//     return methods;
// }
// // Test the parser with sample C code
// async function testParser() {
//     const code = `
//         int add(int a, int b) {
//             return a + b;
//         }

//         void greet() {
//             printf("Hello, World!");
//         }
//     `;

//     const functions = await parseCCode(code);
//     console.log("Extracted Functions:", functions);
// }

// testParser();

