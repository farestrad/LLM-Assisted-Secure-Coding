import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';


/**
 * Check for other vulnerabilities in a method. (Minhyeok)
 */
export class OtherVulnerabilitiesCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const vulnerabilities = new Map<string, Set<string>>();


    // Get configuration from VSCode
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const commandInjectionFunctions = config.get<string[]>('commandInjectionFunctions', ['system', 'popen', 'exec', 'fork', 'wait', 'systemp']);
    const hardcodedCredentialsKeywords = config.get<string[]>('hardcodedCredentialsKeywords', ['password', 'secret', 'apikey', 'token', 'key']);
    const weakCryptoAlgorithms = config.get<string[]>('weakCryptoAlgorithms', ['MD5', 'SHA1']);
    const improperInputFunctions = config.get<string[]>('improperInputFunctions', ['atoi', 'atol', 'atof', 'gets', 'scanf']);
    const improperPrivilegeFunctions = config.get<string[]>('improperPrivilegeFunctions', ['setuid', 'setgid', 'seteuid', 'setegid']);
    const improperSessionFunctions = config.get<string[]>('improperSessionFunctions', ['session_start', 'session_id']);

    let match;

    // Check for command injection
    const commandInjectionPattern = new RegExp(`\\b(${commandInjectionFunctions.join('|')})\\b\\s*\\(`, 'g');
    while ((match = commandInjectionPattern.exec(methodBody)) !== null) {
        const commandInjection = match[1];
        if (!vulnerabilities.has('commandInjection')) {
            vulnerabilities.set('commandInjection', new Set<string>());
        }
        vulnerabilities.get('commandInjection')?.add(commandInjection);
        issues.push(`Warning: Possible command injection vulnerability detected in method "${methodName}". Avoid using system calls with user input.`);
    }
    // const commandInjectionPattern = /\b(system|popen|exec|fork|wait|systemp)\s*\(/g;
    // if (commandInjectionPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Possible command injection vulnerability detected in method "${methodName}". Avoid using system calls with user input.`
    //     );
    // }

    // Check for hardcoded credentials
    const hardCodedPattern = new RegExp(`\\b(${hardcodedCredentialsKeywords.join('|')})\\s*=\\s*["'].*["']`, 'gi');
    while ((match = hardCodedPattern.exec(methodBody)) !== null) {
        const credentials = match[0];
        if (!vulnerabilities.has('hardcodedCredentials')) {
            vulnerabilities.set('hardcodedCredentials', new Set<string>());
        }
        const hardcodedCredentials = vulnerabilities.get('hardcodedCredentials');
        if (hardcodedCredentials) {
            hardcodedCredentials.add(credentials);
        }
        issues.push(`Warning: Hardcoded credentials detected in method "${methodName}". Avoid hardcoding sensitive information.`);
    }
    // const hardCodedPattern = /\b(password|secret|apikey|token|key)\s*=\s*["'].*["']/gi;
    // if (hardCodedPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Hardcoded credentials detected in method "${methodName}". Avoid hardcoding sensitive information.`
    //     );
    // }

    // Check for improper authentication handling
    const authPattern = /\b(==|!=)\s*["'].*["']/;
    while ((match = authPattern.exec(methodBody)) !== null) {
        const comp = match[0];
        if (!vulnerabilities.has('improperAuthentication')) {
            vulnerabilities.set('improperAuthentication', new Set<string>());
        }
        vulnerabilities.get('improperAuthentication')?.add(comp);
        issues.push(`Warning: Improper authentication handling detected in method "${methodName}". Avoid using string comparison for sensitive data.`);
    }
    // const authPattern = /\b(==|!=)\s*["'].*["']/;
    // if (authPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Improper authentication handling detected in method "${methodName}". Avoid using string comparison for sensitive data.`
    //     );
    // }

    // Check for insecure cryptographic storage
    const cryptoPattern = new RegExp(`\\b(${weakCryptoAlgorithms.join('|')})\\b`, 'gi');
    while ((match = cryptoPattern.exec(methodBody)) !== null) {
        const algorithm = match[0];
        if (!vulnerabilities.has('weakCryptoAlgorithms')) {
            vulnerabilities.set('weakCryptoAlgorithms', new Set<string>());
        }
        vulnerabilities.get('weakCryptoAlgorithms')?.add(algorithm);
        issues.push(`Warning: Insecure cryptographic storage detected in method "${methodName}". Avoid using weak hashing algorithms.`);
    }
    // const cryptoPattern = /\bMD5\b|\bSHA1\b/;
    // if (cryptoPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Insecure cryptographic storage detected in method "${methodName}". Avoid using weak hashing algorithms.`
    //     );
    // }

    // Check for improper error handling and logging
    const errorPattern = /\b(printf|fprintf|stderr|strerror)\s*\(/;
    while ((match = errorPattern.exec(methodBody)) !== null) {
        if (!vulnerabilities.has('improperErrorHandling')) {
            vulnerabilities.set('improperErrorHandling', new Set<string>());
        }
        vulnerabilities.get('improperErrorHandling')?.add(match[0]);
        issues.push(`Warning: Improper error handling and logging detected in method "${methodName}". Ensure proper error messages and logging.`);
    }
    // const errorPattern = /\b(printf|fprintf|stderr|strerror)\s*\(/;
    // if (errorPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Improper error handling and logging detected in method "${methodName}". Ensure proper error messages and logging.`
    //     );
    // }

    // Check for improper input validation
    const inputPattern = new RegExp(`\\b(${improperInputFunctions.join('|')})\\s*\\(`, 'g');
    while ((match = inputPattern.exec(methodBody)) !== null) {
        const inputFunction = match[1];
        if (!vulnerabilities.has('improperInputValidation')) {
            vulnerabilities.set('improperInputValidation', new Set<string>());
        }
        vulnerabilities.get('improperInputValidation')?.add(inputFunction);
        issues.push(`Warning: Improper input validation detected in method "${methodName}". Ensure proper input validation and sanitization.`);
    }
    // const inputPattern = /\batoi\(|atol\(|atof\(|gets\(|scanf\(/;
    // if (inputPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Improper input validation detected in method "${methodName}". Ensure proper input validation and sanitization.`
    //     );
    // }

    // Check for improper privilege management
    const privilegePattern = new RegExp(`\\b(${improperPrivilegeFunctions.join('|')})\\s*\\(`, 'g');
    while ((match = privilegePattern.exec(methodBody)) !== null) {
        const privilegeFunction = match[1];
        if (!vulnerabilities.has('improperPrivilegeManagement')) {
            vulnerabilities.set('improperPrivilegeManagement', new Set<string>());
        }
        vulnerabilities.get('improperPrivilegeManagement')?.add(privilegeFunction);
        issues.push(`Warning: Improper privilege management detected in method "${methodName}". Avoid using setuid, setgid, seteuid, and setegid.`);
    }
    // const privilegePattern = /\b(setuid|setgid|seteuid|setegid)\s*\(/;
    // if (privilegePattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Improper privilege management detected in method "${methodName}". Avoid using setuid, setgid, seteuid, and setegid.`
    //     );
    // }

    // Check for improper session management
    const sessionPattern = new RegExp(`\\b(${improperSessionFunctions.join('|')})\\s*\\(`, 'g');
    while ((match = sessionPattern.exec(methodBody)) !== null) {
        const sessionFunction = match[1];
        if (!vulnerabilities.has('improperSessionManagement')) {
            vulnerabilities.set('improperSessionManagement', new Set<string>());
        }
        vulnerabilities.get('improperSessionManagement')?.add(sessionFunction);
        issues.push(`Warning: Improper session management detected in method "${methodName}". Ensure proper session handling.`);
    }
    // const sessionPattern = /\b(session_start|session_id)\s*\(/;
    // if (sessionPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Improper session management detected in method "${methodName}". Ensure proper session handling.`
    //     );
    // }

    return issues;
    }
}

///////


/**
 * Helper function to check if input is sanitized in a method.
 */
// function isSanitized(input: string, methodBody: string): boolean {
//     const sanitizedPattern = new RegExp(`\\b(sanitize|validate|escape)\\s*\\(\\s*${input}\\s*\\)`, 'i');
//     return sanitizedPattern.test(methodBody);
// }
