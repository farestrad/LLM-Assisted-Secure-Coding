import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { SecurityCheck } from "../c/SecurityCheck";
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';
export class WeakHashingEncryptionCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const weakHashes = new Set<string>();
        const encryptionMethods = new Set<string>();
    let match;

    // Detect weak hashing mechanisms
    const weakHashPattern = /\b(md5|sha1|crypt)\s*\(/gi;
    while ((match = weakHashPattern.exec(methodBody)) !== null) {
        const weakHash = match[1];
        weakHashes.add(weakHash);
        issues.push(`Warning: Weak hashing algorithm (${weakHash}) detected in method "${methodName}". Consider using a strong hash function like bcrypt, scrypt, or Argon2.`);
    }

    // Detect encryption usage for passwords
    const encryptionPattern = /\b(encrypt|aes_encrypt|des_encrypt|blowfish_encrypt|crypto_encrypt|rsa_encrypt)\s*\(/gi;
    while ((match = encryptionPattern.exec(methodBody)) !== null) {
        const encryptionMethod = match[1];
        encryptionMethods.add(encryptionMethod);
        issues.push(
            `Warning: Passwords should not be encrypted using ${encryptionMethod} in method "${methodName}". Use a secure hashing algorithm (e.g., bcrypt, Argon2) instead.`
        );
    }

    // Detect direct calls to insecure hash libraries in code
    const hashLibraryPattern = /\b#include\s*<\s*(openssl\/md5\.h|openssl\/sha\.h)\s*>/g;
    if (hashLibraryPattern.test(methodBody)) {
        issues.push(
            `Warning: Insecure hash library inclusion detected in method "${methodName}". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.`
        );
    }

    return issues;
    }
}
