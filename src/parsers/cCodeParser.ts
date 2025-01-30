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










/*
import { exec } from 'child_process';



export class cCodeParser {
    /**
     * Extracts methods/functions from the given C code using Clang AST.
     * @param code The raw C code as a string.
     * @returns A promise resolving to an array of method information objects.
     
    static async extractMethodsFromAST(code: string): Promise<MethodInfo[]> {
        return new Promise((resolve, reject) => {
            this.getClangAST(code, (ast) => {
                if (!ast) {
                    reject("Failed to parse Clang AST.");
                    return;
                }

                const methods: MethodInfo[] = [];

                function traverse(node: any) {
                    if (node.kind === 'FunctionDecl') {
                        const bodyNode = node.children?.find((n: any) => n.kind === 'CompoundStmt');
                        methods.push({
                            name: node.name,
                            parameters: node.children
                                ?.filter((n: any) => n.kind === 'ParmVarDecl')
                                .map((p: any) => p.name) || [],
                            body: bodyNode ? cCodeParser.getSourceCodeSlice(code, bodyNode.range) : '',
                            range: node.range,
                            ast: node // Store full AST for deeper analysis
                        });
                    }
                    node.children?.forEach(traverse);
                }

                traverse(ast);
                resolve(methods);
            });
        });
    }

    /**
     * Runs Clang AST analysis on the given C code and returns the AST.
     * @param code The raw C code as a string.
     * @param callback A function to handle the parsed AST.
     
    static getClangAST(code: string, callback: (ast: any | null) => void): void {
        exec(`echo "${code}" | clang -Xclang -ast-dump=json -fsyntax-only -xc -`, (err, stdout) => {
            if (err) {
                console.error("Clang AST analysis failed:", err);
                callback(null);
                return;
            }

            try {
                const ast = JSON.parse(stdout);
                callback(ast);
            } catch (error) {
                console.error("Failed to parse Clang AST JSON:", error);
                callback(null);
            }
        });
    }

    /**
     * Extracts a portion of the source code using AST-provided line ranges.
     * @param code The full C source code.
     * @param range The range object containing line numbers.
     * @returns Extracted function body as a string.
     
    private static getSourceCodeSlice(code: string, range: { begin: any; end: any }) {
        const lines = code.split('\n');
        const startLine = range.begin.line - 1;
        const endLine = range.end.line - 1;
        return lines.slice(startLine, endLine + 1).join('\n');
    }
}

/**
 * Represents information about an extracted C method.
 
export interface MethodInfo {
    name: string;
    parameters: string[];
    body: string;
    range: any;
    ast: any;
}


*/