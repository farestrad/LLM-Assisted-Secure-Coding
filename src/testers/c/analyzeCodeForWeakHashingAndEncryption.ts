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
    // Step 1: Detect weak hashing mechanisms
    const weakHashPattern = /\b(MD5|SHA1|crypt|md5|sha1)_?\w*\s*\(/gi;
    while ((match = weakHashPattern.exec(methodBody)) !== null) {
        weakHashes.add(match[1]);
    }

    // Step 2: Explicitly check if weak hashes were found (introduces a branch)
    if (weakHashes.size > 0) {
        weakHashes.forEach(hash => {
            issues.push(`Warning: Weak hashing algorithm (${hash}) detected in method "${methodName}".`);
        });
    } else {
        issues.push(`Info: No weak hashing algorithms found in method "${methodName}".`);
    } //remove later and match bottom


    // Step 1: Detect encryption usage for passwords
    const encryptionPattern = /\b(encrypt|aes_encrypt|des_encrypt|blowfish_encrypt|crypto_encrypt|rsa_encrypt)\s*\(/gi;
    while ((match = encryptionPattern.exec(methodBody)) !== null) {
        encryptionMethods.add(match[1]);
    }

    // Step 2: Explicitly check if encryption methods were found
    if (encryptionMethods.size > 0) {
        encryptionMethods.forEach(method => {
            issues.push(`Warning: Passwords should not be encrypted using ${method} in method "${methodName}".`);
        });
    } else {
        issues.push(`Info: No encryption-related vulnerabilities found in method "${methodName}".`);
    }

    // Detect direct calls to insecure hash libraries in code
    const hashLibraryPattern = /\b#include\s*[<"]?\s*openssl\/(md5|sha)\.h\s*[>"]?/gi;
    
    if (hashLibraryPattern.test(methodBody)) {
        //issues.push(
        //    `Warning: Insecure hash library inclusion detected in method "${methodName}". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.`
        //); put nack
    }

    return issues;
    }
}
