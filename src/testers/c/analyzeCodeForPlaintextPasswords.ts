
import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { SecurityCheck } from "../c/SecurityCheck";
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';


/**
 * Analyze a method for potential plaintext password vulnerabilities. 
 */
export class PlaintextPasswordCheck implements SecurityCheck{
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const passwordVariables = new Set<string>();
        const fileWriteOperations = new Set<string>();


    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const passwordKeywords = config.get<string[]>('passwordkeywords', ['pass', 'password', 'passwd', 'pwd', 'user_password', 'admin_password', 
        'auth_pass', 'login_password', 'secure_password', 'db_password', 'secret_key', 'passphrase', 'master_password'
    ]);

    // Phase 1: Password Variable Detection
    const passwordPattern = new RegExp(`\\b(${passwordKeywords.join('|')})\\b\\s*=\\s*["']?.+?["']?`, 'gi');
    let match;
    
    while ((match = passwordPattern.exec(methodBody)) !== null) {
        const passwordVar = match[1];
        passwordVariables.add(passwordVar);
        issues.push( 'Warning: Potential password variable (' + passwordVar + ') detected in method "' + methodName + '". Ensure it is not stored in plaintext.');
    }

    // Phase 2: File Write Operation Detection
    const fileWritePattern = /\b(fwrite|fprintf|write|ofstream|fputs)\s*\(\s*[^,]+/g;
    while ((match = fileWritePattern.exec(methodBody)) !== null) {
        fileWriteOperations.add(match[1]);
        issues.push('Warning: File write operation detected in method "' + methodName + '". Ensure sensitive data is encrypted before storage.');
    }

    // Phase 3: Risky Password Checks
    const riskyPasswordChecks = [{
        pattern: /\b(printf|sprintf|fprintf|fwrite|fputs)\s*\(\s*([\w\d_]+)\s*[,)]/g,
        handler: (fn: string, buffer: string) => {
            if (passwordVariables.has(buffer)) {
                return `Potential plaintext password passed to ${fn}`;
            }
            return null;
        }
    },
    {
        pattern: /\b(log|console\.log|System\.out\.println)\s*\(\s*([\w\d_]+)\s*[,)]/g,
        handler: (fn: string, arg: string) => {
            if (passwordVariables.has(arg)) {
                return `Potential plaintext password logged by ${fn}`;
            }
            return null;
        }
    }];

    riskyPasswordChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2]);
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });

    // function isPasswordVariable(variable: string): boolean {
    //     return Array.from(passwordVariables).some((passwordVar) => new RegExp(`\\b${passwordVar}\\b`).test(variable));
    // }
    // Look for password-related variables
    while ((match = passwordPattern.exec(methodBody)) !== null) {
        const passwordVar = match[0];
        issues.push(
            `Warning: Potential password variable (${passwordVar}) detected in method "${methodName}". Ensure it is not stored in plaintext.`
        );
    }

    // Look for file write operations involving password variables
    while ((match = fileWritePattern.exec(methodBody)) !== null) {
        issues.push(
            `Warning: File write operation detected in method "${methodName}". Ensure sensitive data is encrypted before storage.`
        );
    }

    return issues;
}
}