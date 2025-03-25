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

export class WeakHashingEncryptionCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const weakHashes = new Set<string>();
        const weakEncryptionCalls = new Set<string>();
        let match;

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const weakHashFunctions = config.get<string[]>('weakHashFunctions', ['MD5', 'SHA1', 'crypt', 'md5', 'sha1']);
        const weakEncryptFunctions = config.get<string[]>('weakEncryptFunctions', [
            'encrypt', 'aes_encrypt', 'des_encrypt', 'blowfish_encrypt', 'crypto_encrypt', 'rsa_encrypt'
        ]);

        // 🔹 Phase 1: Parse and inspect function calls via AST
        initParser();
        const tree = parser.parse(methodBody);

        function traverse(node: Parser.SyntaxNode) {
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';

                // Match hash functions
                if (weakHashFunctions.some(w => fnName.toLowerCase().includes(w.toLowerCase()))) {
                    weakHashes.add(fnName);
                }

                // Match encryption functions
                if (weakEncryptFunctions.some(enc => fnName.toLowerCase().includes(enc.toLowerCase()))) {
                    weakEncryptionCalls.add(fnName);
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

        // 🔹 Phase 2: Generate issues
        weakHashes.forEach(hashFn => {
            issues.push(
                `Warning: Weak hashing function "${hashFn}" detected in method "${methodName}". Consider using secure options like SHA-256 or bcrypt.`
            );
        });

        weakEncryptionCalls.forEach(encFn => {
            issues.push(
                `Warning: Encryption method "${encFn}" may not be secure for password storage in method "${methodName}". Use proper password hashing (e.g., Argon2, bcrypt).`
            );
        });

        // 🔹 Phase 3: Detect insecure hash library includes (regex only)
        const hashLibraryPattern = /#include\s*[<"]?\s*openssl\/(md5|sha)\.h\s*[>"]?/gi;
        if ((match = hashLibraryPattern.exec(methodBody)) !== null) {
            issues.push(
                `Warning: Insecure hash library inclusion detected in method "${methodName}". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries.`
            );
        }

        return issues;
    }
}
