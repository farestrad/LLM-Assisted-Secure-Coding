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
        
        // Get configuration for detection sensitivity
        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const detectionLevel = config.get<string>('cryptoDetectionLevel', 'moderate');
        
        // Context tracking for better analysis
        const context = {
            // Track weak algorithms and their usages
            weakHashes: new Map<string, {node: Parser.SyntaxNode, algorithm: string}>(),
            weakEncryptions: new Map<string, {node: Parser.SyntaxNode, algorithm: string}>(),
            weakAliasMap: new Map<string, string>(),
            
            // Track crypto usages by purpose to reduce false positives
            passwordContext: false,
            checksumContext: false,
            networkContext: false,
            
            // Track include statements and library usage
            includes: new Set<string>(),
            
            // Track hard-coded keys, IVs, salts
            hardcodedSecrets: new Map<string, {node: Parser.SyntaxNode, type: string}>(),
            
            // Track crypto operations
            cryptoOperations: new Map<string, {
                node: Parser.SyntaxNode,
                operation: string,
                inputs: Set<string>,
                outputs: Set<string>
            }>(),
            
            // Track ECB mode usage
            ecbModeUsage: new Set<Parser.SyntaxNode>(),
            
            // Track RNG usage
            rngUsage: new Map<string, Parser.SyntaxNode>(),
        };
        
        // Enhanced lists of weak algorithms and risky functions
        const weakHashFunctions = config.get<string[]>('weakHashFunctions', [
            'MD5', 'SHA1', 'md5', 'sha1', 'md4', 'md2', 'sha0',
            'crypt', 'CRC32', 'adler32'
        ]);
        
        const moderateHashFunctions = [
            'SHA224', 'sha224', 'SHA256', 'sha256', 'SHA384', 'sha384'
        ];
        
        const strongHashFunctions = [
            'SHA512', 'sha512', 'SHA3', 'sha3', 'BLAKE2', 'blake2',
            'bcrypt', 'scrypt', 'PBKDF2', 'pbkdf2', 'Argon2', 'argon2'
        ];
        
        // Encryption algorithms categorized by strength
        const weakEncryptionAlgorithms = [
            'DES', 'des', 'RC2', 'rc2', 'RC4', 'rc4', 'Blowfish', 'blowfish',
            'IDEA', 'idea', 'CAST5', 'cast5', 'SEED', 'seed', 'SKIPJACK', 'skipjack'
        ];
        
        const weakEncryptFunctions = config.get<string[]>('weakEncryptFunctions', [
            'encrypt', 'aes_encrypt', 'des_encrypt', 'blowfish_encrypt', 
            'crypto_encrypt', 'rsa_encrypt', '3des_encrypt', 'triple_des',
            'CAST_encrypt', 'rc4_encrypt', 'rc2_encrypt'
        ]);
        
        // Encryption modes considered weak
        const weakEncryptionModes = [
            'ECB', 'ecb', 'CFB8', 'cfb8', 'OFB', 'ofb'
        ];
        
        // Key size thresholds for different algorithms
        const minimumKeySizes = {
            'RSA': 2048,
            'DSA': 2048,
            'ECC': 256,
            'AES': 128,
            'DH': 2048,
            'ECDH': 256
        };
        
        // Insecure crypto libraries and headers
        const insecureLibraries = [
            '<openssl/md5.h>', '<openssl/sha.h>', '<openssl/des.h>',
            '<openssl/rc4.h>', '<openssl/rc2.h>', '<crypto/md5.h>',
            '<md5.h>', '<sha1.h>', '<des.h>'
        ];
        
        // Prefixes/suffixes that may indicate password contexts
        const passwordContextKeywords = [
            'pass', 'password', 'passwd', 'pw', 'pwd', 'auth', 'cred',
            'credential', 'secret', 'key', 'private', 'hash', 'login'
        ];
        
        // Helper: Add line numbers for better reporting
        function formatLineInfo(node: Parser.SyntaxNode): string {
            return `line ${node.startPosition.row + 1}`;
        }
        
        // Helper: Match function name against pattern lists
        function matchAlgorithm(name: string, patternList: string[]): boolean {
            return patternList.some(pattern => 
                new RegExp(`\\b${pattern}\\b`, 'i').test(name)
            );
        }
        
        // Helper: Check if we're in a password-related context
        function isPasswordContext(text: string): boolean {
            return passwordContextKeywords.some(keyword => 
                new RegExp(`\\b${keyword}\\b`, 'i').test(text)
            );
        }
        
        // Helper: Check if a string might be a hard-coded secret
        function isLikelySecret(value: string): boolean {
            const cleanValue = value.replace(/['"]/g, '').trim();
            
            // Ignore very short strings and empty strings
            if (cleanValue.length < 8) return false;
            
            // Check for hex strings that might be keys
            const isHexString = /^[A-Fa-f0-9]{16,}$/.test(cleanValue);
            
            // Check for base64-looking strings
            const isBase64 = /^[A-Za-z0-9+/]{20,}={0,2}$/.test(cleanValue);
            
            // Check for obvious key labels
            const hasKeyLabel = /key|password|secret|token|iv|nonce/i.test(cleanValue);
            
            return isHexString || isBase64 || hasKeyLabel;
        }
        
        // Check for weak key sizes
        function analyzeKeySize(node: Parser.SyntaxNode): {algorithm: string, size: number} | null {
            // Look for key generation functions and size parameters
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const argList = node.child(1);
                
                // Check common key generation functions
                if (/generate_key|create_key|new_key|gen_key|key_gen|keygen/i.test(fnName)) {
                    // Look for size parameter
                    const sizeArg = argList?.namedChildren[0] || argList?.namedChildren[1];
                    if (sizeArg && sizeArg.type === 'number_literal') {
                        const size = parseInt(sizeArg.text, 10);
                        
                        // Try to determine the algorithm
                        let algorithm = 'unknown';
                        if (/rsa/i.test(fnName)) algorithm = 'RSA';
                        else if (/dsa/i.test(fnName)) algorithm = 'DSA';
                        else if (/ec/i.test(fnName)) algorithm = 'ECC';
                        else if (/aes/i.test(fnName)) algorithm = 'AES';
                        else if (/dh/i.test(fnName)) algorithm = 'DH';
                        
                        return { algorithm, size };
                    }
                }
            }
            
            return null;
        }
        
        // Check for weak ECB mode usage
        function checkForEcbMode(node: Parser.SyntaxNode): boolean {
            const nodeText = node.text.toLowerCase();
            
            // Simple pattern matching for ECB mode
            if (/ecb|electronic.*code.*book/i.test(nodeText)) {
                return true;
            }
            
            // Check for mode settings in common crypto libraries
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                
                if (/set_mode|init|encrypt|EVP_.*_ecb/i.test(fnName)) {
                    const args = node.child(1)?.text || '';
                    if (/ecb|MODE_ECB/i.test(args)) {
                        return true;
                    }
                }
            }
            
            return false;
        }
        
        // Parse the code
        initParser();
        const tree = parser.parse(methodBody);
        
        // First pass: Check for include statements and context indicators
        function firstPassAnalysis(node: Parser.SyntaxNode) {
            // Detect include statements
            if (node.type === 'preproc_include') {
                const includePath = node.text.replace('#include', '').trim();
                context.includes.add(includePath);
                
                // Check for insecure libraries
                for (const lib of insecureLibraries) {
                    if (includePath.includes(lib)) {
                        issues.push(
                            `Warning: Including insecure cryptographic library "${lib}" at ${formatLineInfo(node)} in method "${methodName}". Use modern cryptographic libraries instead.`
                        );
                    }
                }
            }
            
            // Detect password contexts
            if (node.type === 'identifier' || node.type === 'field_identifier') {
                if (isPasswordContext(node.text)) {
                    context.passwordContext = true;
                }
            }
            
            // Check comments for additional context
            if (node.type.includes('comment')) {
                const comment = node.text.toLowerCase();
                if (/password|authentication|login|credential|secret/i.test(comment)) {
                    context.passwordContext = true;
                }
                if (/checksum|hash|signature|integrity/i.test(comment)) {
                    context.checksumContext = true;
                }
                if (/network|socket|http|https|ssl|tls/i.test(comment)) {
                    context.networkContext = true;
                }
            }
            
            // Recursively process children
            node.namedChildren.forEach(firstPassAnalysis);
        }
        
        // Main pass: Identify crypto issues
        function mainAnalysis(node: Parser.SyntaxNode) {
            // Check assignments for aliases and weak functions
            if (node.type === 'init_declarator' || node.type === 'assignment_expression') {
                const lhs = node.namedChildren.find(child => 
                    child.type.includes('declarator') || 
                    child.type === 'identifier'
                );
                
                const rhs = node.namedChildren.find(child => 
                    child.type === 'identifier' || 
                    child.type === 'call_expression' ||
                    child.type === 'string_literal'
                );
                
                if (lhs && rhs) {
                    const lhsName = lhs.text;
                    const rhsText = rhs.text;
                    
                    // Track aliases
                    if (rhs.type === 'identifier') {
                        const resolvedRhs = context.weakAliasMap.get(rhsText) || rhsText;
                        
                        if (matchAlgorithm(resolvedRhs, weakHashFunctions)) {
                            context.weakAliasMap.set(lhsName, resolvedRhs);
                            context.weakHashes.set(lhsName, {
                                node: node,
                                algorithm: resolvedRhs
                            });
                        }
                        
                        if (matchAlgorithm(resolvedRhs, weakEncryptionAlgorithms) || 
                            matchAlgorithm(resolvedRhs, weakEncryptFunctions)) {
                            context.weakAliasMap.set(lhsName, resolvedRhs);
                            context.weakEncryptions.set(lhsName, {
                                node: node,
                                algorithm: resolvedRhs
                            });
                        }
                    }
                    
                    // Check for hard-coded secrets
                    if (rhs.type === 'string_literal' && isLikelySecret(rhsText)) {
                        let secretType = 'unknown';
                        
                        // Determine type based on variable name
                        if (/key|secret/i.test(lhsName)) secretType = 'key';
                        else if (/iv|vector|nonce/i.test(lhsName)) secretType = 'iv';
                        else if (/salt/i.test(lhsName)) secretType = 'salt';
                        else if (/pass/i.test(lhsName)) secretType = 'password';
                        
                        context.hardcodedSecrets.set(lhsName, {
                            node: node,
                            type: secretType
                        });
                        
                        issues.push(
                            `Warning: Hard-coded ${secretType} detected in "${lhsName}" at ${formatLineInfo(node)} in method "${methodName}". Avoid embedding cryptographic secrets in code.`
                        );
                    }
                }
            }
            
            // Check function calls
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text || '';
                const resolvedFn = context.weakAliasMap.get(fnName) || fnName;
                
                // Check for weak hashing
                if (matchAlgorithm(resolvedFn, weakHashFunctions)) {
                    context.weakHashes.set(fnName, {
                        node: node,
                        algorithm: resolvedFn
                    });
                    
                    const severity = context.passwordContext ? "Critical" : "Warning";
                    const recommendation = context.passwordContext ?
                        "Use strong password hashing like bcrypt, Argon2, or PBKDF2." :
                        "Consider using SHA-256 or stronger.";
                    
                    issues.push(
                        `${severity}: Weak hashing algorithm "${resolvedFn}" at ${formatLineInfo(node)} in method "${methodName}". ${recommendation}`
                    );
                }
                
                // Check for weak encryption
                if (matchAlgorithm(resolvedFn, weakEncryptionAlgorithms) || 
                    matchAlgorithm(resolvedFn, weakEncryptFunctions)) {
                    context.weakEncryptions.set(fnName, {
                        node: node,
                        algorithm: resolvedFn
                    });
                    
                    const severity = context.passwordContext ? "Critical" : "Warning";
                    issues.push(
                        `${severity}: Weak encryption algorithm "${resolvedFn}" at ${formatLineInfo(node)} in method "${methodName}". Use modern algorithms like AES-256-GCM.`
                    );
                }
                
                // Check for ECB mode
                if (checkForEcbMode(node)) {
                    context.ecbModeUsage.add(node);
                    issues.push(
                        `Warning: Insecure ECB mode detected at ${formatLineInfo(node)} in method "${methodName}". Use CBC, CTR, or GCM modes instead.`
                    );
                }
                
                // Check key sizes
                const keySizeInfo = analyzeKeySize(node);
                if (keySizeInfo) {
                    const { algorithm, size } = keySizeInfo;
                
                    if (Object.prototype.hasOwnProperty.call(minimumKeySizes, algorithm)) {
                        const minSize = minimumKeySizes[algorithm as keyof typeof minimumKeySizes];
                        if (size < minSize) {
                            issues.push(
                                `Warning: Insufficient key size (${size} bits) for ${algorithm} at ${formatLineInfo(node)} in method "${methodName}". Minimum recommended size is ${minSize} bits.`
                            );
                        }
                    }
                }
                
                
                // Check for RNG usage
                if (/random|rand|srandom|srand/i.test(fnName)) {
                    // Skip warnings in relaxed mode unless it's a critical RNG issue
                    if (detectionLevel !== 'relaxed' || /^rand$|^random$/.test(fnName)) {
                        const isCryptoRng = /crypto|secure|csprng/i.test(fnName);
                        
                        if (!isCryptoRng && (context.passwordContext || /key|iv|nonce|salt/i.test(methodName))) {
                            issues.push(
                                `Warning: Potentially insecure random number generator "${fnName}" used in cryptographic context at ${formatLineInfo(node)} in method "${methodName}". Use a cryptographically secure RNG.`
                            );
                        }
                    }
                }
            }
            
            // Check for field expressions
            if (node.type === 'field_expression') {
                const fieldName = node.child(node.namedChildCount - 1)?.text || '';
                
                // Check for weak encryption/hash settings in fields
                if (matchAlgorithm(fieldName, [...weakHashFunctions, ...weakEncryptionAlgorithms])) {
                    issues.push(
                        `Warning: Weak cryptographic algorithm "${fieldName}" referenced at ${formatLineInfo(node)} in method "${methodName}".`
                    );
                }
                
                // Check for ECB mode in fields
                if (checkForEcbMode(node)) {
                    context.ecbModeUsage.add(node);
                    issues.push(
                        `Warning: Insecure ECB mode referenced at ${formatLineInfo(node)} in method "${methodName}". Use CBC, CTR, or GCM modes instead.`
                    );
                }
            }
            
            // Recursively process children
            node.namedChildren.forEach(mainAnalysis);
        }
        
        // Run analysis passes
        firstPassAnalysis(tree.rootNode);
        mainAnalysis(tree.rootNode);
        
        // Final analysis: Check if we've issued warnings proportional to detection level
        if (detectionLevel === 'relaxed') {
            // Filter to only show the most severe warnings
            return issues.filter(issue => issue.startsWith('Critical'));
        }
        
        return issues;
    }
}