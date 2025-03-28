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
        const weakAliasMap = new Map<string, string>();

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const weakHashFunctions = config.get<string[]>('weakHashFunctions', ['MD5', 'SHA1', 'crypt', 'md5', 'sha1']);
        const weakEncryptFunctions = config.get<string[]>('weakEncryptFunctions', [
            'encrypt', 'aes_encrypt', 'des_encrypt', 'blowfish_encrypt', 'crypto_encrypt', 'rsa_encrypt','encrypt', 'aes_encrypt'
        ]);

        //  Phase 1: Parse and inspect function calls and assignments via AST
        initParser();
        const tree = parser.parse(methodBody);

        function matchWeak(fn: string, list: string[]): boolean {
            //return list.some(w => fn.toLowerCase().includes(w.toLowerCase()));
            return list.some(w => new RegExp(`\\b${w}\\b`, 'i').test(fn))
        }
        

        function traverse(node: Parser.SyntaxNode) {

            if (node.type === 'init_declarator' || node.type === 'assignment_expression') {
                const lhs = node.namedChildren.find(child => child.type.includes('declarator') || child.type === 'identifier');
                const rhs = node.namedChildren.find(child => child.type === 'identifier');
            
                if (lhs && rhs) {
                    const alias = lhs.text;
                    const assigned = rhs.text;
            
                    if (matchWeak(assigned, weakEncryptFunctions)) {
                        weakEncryptionCalls.add(assigned);
                        weakAliasMap.set(alias, assigned);
                    }
                    if (matchWeak(assigned, weakHashFunctions)) {
                        weakHashes.add(assigned);
                        weakAliasMap.set(alias, assigned);
                    }
                }
            }
            
            
            
            //  Function call detection
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const resolvedFn = weakAliasMap.get(fnName) || fnName;
            
                if (matchWeak(resolvedFn, weakHashFunctions)) {
                    weakHashes.add(resolvedFn);
                }
                if (matchWeak(resolvedFn, weakEncryptFunctions)) {
                    weakEncryptionCalls.add(resolvedFn);
                }
            }
            

            //  Assignment (e.g., fn_ptr = MD5)
            if (node.type === 'assignment_expression') {
                const rhs = node.child(2)?.text || '';
                if (matchWeak(rhs, weakHashFunctions)) {
                    weakHashes.add(rhs);
                }
                if (matchWeak(rhs, weakEncryptFunctions)) {
                    weakEncryptionCalls.add(rhs);
                }
            }

            // 🔸 Field assignment (e.g., ctx->hash = SHA1)
            if (node.type === 'field_expression') {
                const rhs = node.child(2)?.text || '';
                if (matchWeak(rhs, weakHashFunctions)) {
                    weakHashes.add(rhs);
                }
                if (matchWeak(rhs, weakEncryptFunctions)) {
                    weakEncryptionCalls.add(rhs);
                }
            }

            node.namedChildren.forEach(traverse);
        }

        traverse(tree.rootNode);

      
  //  Phase 2: Report matches
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

        return issues;
    }
}
