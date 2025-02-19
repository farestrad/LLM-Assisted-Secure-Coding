import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { SecurityCheck } from "../c/SecurityCheck";
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';


/**
 * Check for other vulnerabilities in a method. (Minhyeok)
 **/
export class OtherVulnerabilitiesCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const vulnerabilities = new Map<string, Set<string>>();

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
        commandInjectionPattern.lastIndex = 0;
        while ((match = commandInjectionPattern.exec(methodBody)) !== null) {
            if (!match[0]) break; // Prevent infinite loop if match is empty
            vulnerabilities.set('commandInjection', (vulnerabilities.get('commandInjection') || new Set()).add(match[1]));
            issues.push(`Warning: Possible command injection vulnerability detected in method "${methodName}". Avoid using system calls with user input.`);
            commandInjectionPattern.lastIndex = match.index + match[0].length; // Ensure regex progresses
        }

        // Check for hardcoded credentials
        const hardCodedPattern = new RegExp(`\\b(${hardcodedCredentialsKeywords.join('|')})\\s*=\\s*["'].*["']`, 'gi');
        hardCodedPattern.lastIndex = 0;
        while ((match = hardCodedPattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('hardcodedCredentials', (vulnerabilities.get('hardcodedCredentials') || new Set()).add(match[0]));
            issues.push(`Warning: Hardcoded credentials detected in method "${methodName}". Avoid hardcoding sensitive information.`);
            hardCodedPattern.lastIndex = match.index + match[0].length;
        }

        // Check for improper authentication handling
        const authPattern = /(==|!=)\s*["'].*["']/g; // removing \b
        authPattern.lastIndex = 0;
        while ((match = authPattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('improperAuthentication', (vulnerabilities.get('improperAuthentication') || new Set()).add(match[0]));
            issues.push(`Warning: Improper authentication handling detected in method "${methodName}". Avoid using string comparison for sensitive data.`);
            authPattern.lastIndex = match.index + match[0].length;
        }

        // Check for insecure cryptographic storage
        const cryptoPattern = new RegExp(`\\b(${weakCryptoAlgorithms.join('|')})\\b`, 'gi');
        cryptoPattern.lastIndex = 0;
        while ((match = cryptoPattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('weakCryptoAlgorithms', (vulnerabilities.get('weakCryptoAlgorithms') || new Set()).add(match[0]));
            issues.push(`Warning: Insecure cryptographic storage detected in method "${methodName}". Avoid using weak hashing algorithms.`);
            cryptoPattern.lastIndex = match.index + match[0].length;
        }

        // Check for improper error handling and logging
        const errorPattern = /\b(printf|fprintf|stderr|strerror)\s*\(/g;
        errorPattern.lastIndex = 0;
        while ((match = errorPattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('improperErrorHandling', (vulnerabilities.get('improperErrorHandling') || new Set()).add(match[0]));
            issues.push(`Warning: Improper error handling and logging detected in method "${methodName}". Ensure proper error messages and logging.`);
            errorPattern.lastIndex = match.index + match[0].length;
        }

        // Check for improper input validation
        const inputPattern = new RegExp(`\\b(${improperInputFunctions.join('|')})\\s*\\(`, 'g');
        inputPattern.lastIndex = 0;
        while ((match = inputPattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('improperInputValidation', (vulnerabilities.get('improperInputValidation') || new Set()).add(match[1]));
            issues.push(`Warning: Improper input validation detected in method "${methodName}". Ensure proper input validation and sanitization.`);
            inputPattern.lastIndex = match.index + match[0].length;
        }

        // Check for improper privilege management
        const privilegePattern = new RegExp(`\\b(${improperPrivilegeFunctions.join('|')})\\s*\\(`, 'g');
        privilegePattern.lastIndex = 0;
        while ((match = privilegePattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('improperPrivilegeManagement', (vulnerabilities.get('improperPrivilegeManagement') || new Set()).add(match[1]));
            issues.push(`Warning: Improper privilege management detected in method "${methodName}". Avoid using setuid, setgid, seteuid, and setegid.`);
            privilegePattern.lastIndex = match.index + match[0].length;
        }

        // Check for improper session management
        const sessionPattern = new RegExp(`\\b(${improperSessionFunctions.join('|')})\\s*\\(`, 'g');
        sessionPattern.lastIndex = 0;
        while ((match = sessionPattern.exec(methodBody)) !== null) {
            if (!match[0]) break;
            vulnerabilities.set('improperSessionManagement', (vulnerabilities.get('improperSessionManagement') || new Set()).add(match[1]));
            issues.push(`Warning: Improper session management detected in method "${methodName}". Ensure proper session handling.`);
            sessionPattern.lastIndex = match.index + match[0].length;
        }

        return issues;
    }
}
