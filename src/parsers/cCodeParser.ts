import { exec } from 'child_process';

export class cCodeParser {
    /**
     * Extracts methods/functions from the given code.
     * @param code The raw C code as a string.
     * @returns Array of objects containing method name, parameters, and body.
     */
    static extractMethods(code: string): { name: string; parameters: string[]; body: string }[] {
        const methodPattern = /\b(\w+)\s+(\w+)\s*\(([^)]*)\)\s*{([\s\S]*?)}/g;
        const methods: { name: string; parameters: string[]; body: string }[] = [];
        let match;

        while ((match = methodPattern.exec(code)) !== null) {
            methods.push({
                name: match[2], // Function name
                parameters: match[3] ? match[3].split(',').map((p) => p.trim()) : [],
                body: match[4], // Function body
            });
        }

        return methods;
    }

    /**
     * Runs Clang AST analysis on the given C code and returns the AST.
     * @param code The raw C code as a string.
     * @param callback A function to handle the parsed AST.
     */
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
}
