import * as vscode from 'vscode';
import { SecurityCheck } from "../c/SecurityCheck";
import Parser from 'tree-sitter';
import C from 'tree-sitter-c';

let parser: Parser;

function initParser() {
    if (!parser) {
        parser = new Parser();
        parser.setLanguage(C as unknown as Parser.Language);
    }
}

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

        // Initialize the parser and parse the methodBody
        initParser();
        const tree = parser.parse(methodBody);
        
        // Function to recursively traverse AST nodes and check for vulnerabilities
        function traverseNode(node: Parser.SyntaxNode) {
            // Phase 1: Check for command injection functions
            if (node.type === 'call_expression') {
                const funcName = node.child(0)?.text || '';
                if (commandInjectionFunctions.includes(funcName)) {
                    issues.push(`Warning: Possible command injection in method "${methodName}". Avoid using ${funcName} with user input.`);
                    vulnerabilities.set('commandInjection', (vulnerabilities.get('commandInjection') || new Set()).add(funcName));
                }
            }

            // Phase 2: Check for improper input functions (e.g., gets, atoi)
            if (node.type === 'call_expression') {
                const funcName = node.child(0)?.text || '';
                if (improperInputFunctions.includes(funcName)) {
                    issues.push(`Warning: Improper input validation in method "${methodName}". Avoid using ${funcName}.`);
                    vulnerabilities.set('improperInputValidation', (vulnerabilities.get('improperInputValidation') || new Set()).add(funcName));
                }
            }

            // Phase 3: Check for improper privilege functions (e.g., setuid, setgid)
            if (node.type === 'call_expression') {
                const funcName = node.child(0)?.text || '';
                if (improperPrivilegeFunctions.includes(funcName)) {
                    issues.push(`Warning: Improper privilege management in method "${methodName}". Avoid using ${funcName}.`);
                    vulnerabilities.set('improperPrivilegeManagement', (vulnerabilities.get('improperPrivilegeManagement') || new Set()).add(funcName));
                }
            }

            // Check all children of the current node
            node.namedChildren.forEach(traverseNode);
        }

        // Start AST traversal
        traverseNode(tree.rootNode);

        // Phase 4: Regex checks for hardcoded credentials and weak crypto algorithms
        const hardCodedPattern = new RegExp(`\\b(${hardcodedCredentialsKeywords.join('|')})\\s*=\\s*["'].*["']`, 'gi');
        let match;
        while ((match = hardCodedPattern.exec(methodBody)) !== null) {
            issues.push(`Warning: Hardcoded credentials detected in method "${methodName}". Avoid hardcoding sensitive information.`);
        }

        const cryptoPattern = new RegExp(`\\b(${weakCryptoAlgorithms.join('|')})\\b`, 'gi');
        const matchedAlgos = new Set<string>();
        while ((match = cryptoPattern.exec(methodBody)) !== null) {
            const algo = match[1];
            if (!matchedAlgos.has(algo)) {
                issues.push(`Warning: Weak cryptographic algorithm detected in method "${methodName}". Avoid using ${algo}.`);
                matchedAlgos.add(algo);
            }
        }


        return issues;
    }
}
