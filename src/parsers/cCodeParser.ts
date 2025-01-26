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
