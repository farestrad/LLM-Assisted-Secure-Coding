import * as vscode from 'vscode';
import { runCTests } from './testers/cTester';
import { GeneratedCodeProvider } from './generatedCodeProvider';

const TOP_CWES = [
        {
            id: 79,
            name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."
        },
        {
            id: 787,
            name: "Out-of-bounds Write",
            description: "The software writes data past the end, or before the beginning, of the intended buffer."
        },
        {
            id: 89,
            name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize special elements that could modify the intended SQL command."
        },
        {
            id: 352,
            name: "Cross-Site Request Forgery (CSRF)",
            description: "An attacker tricks a user into executing unwanted actions on a web application where they are authenticated, leading to unauthorized operations."
        },
        {
            id: 22,
            name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            description: "The application allows user input to access files outside of the intended directory, potentially exposing sensitive data or enabling code execution."
        },
        {
            id: 125,
            name: "Out-of-bounds Read",
            description: "The software reads data outside the allocated memory buffer, potentially leaking sensitive data or causing crashes."
        },
        {
            id: 78,
            name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            description: "User-controllable input is improperly sanitized before being included in system commands, allowing attackers to execute arbitrary OS commands."
        },
        {
            id: 416,
            name: "Use After Free",
            description: "The software continues to use memory after it has been freed, leading to undefined behavior, crashes, or arbitrary code execution."
        },
        {
            id: 862,
            name: "Missing Authorization",
            description: "The system does not properly check if a user has permission before granting access to a resource or function."
        },
        {
            id: 434,
            name: "Unrestricted Upload of File with Dangerous Type",
            description: "The application allows users to upload files without verifying their type, potentially leading to execution of malicious files on the server."
        },
        {
            id: 94,
            name: "Improper Control of Generation of Code ('Code Injection')",
            description: "User input is used in dynamically generated code without proper validation, leading to arbitrary code execution."
        },
        {
            id: 20,
            name: "Improper Input Validation",
            description: "The application does not properly validate user input, leading to unexpected behavior, security vulnerabilities, or crashes."
        },
        {
            id: 77,
            name: "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
            description: "User input is not properly sanitized before being included in commands, allowing execution of arbitrary commands."
        },
        {
            id: 287,
            name: "Improper Authentication",
            description: "The system does not properly verify the identity of users, allowing unauthorized access to protected functions."
        },
        {
            id: 269,
            name: "Improper Privilege Management",
            description: "The application fails to enforce proper privilege levels, allowing attackers to escalate their access."
        },
        {
            id: 502,
            name: "Deserialization of Untrusted Data",
            description: "Untrusted data is deserialized without validation, potentially allowing attackers to execute arbitrary code."
        },
        {
            id: 200,
            name: "Exposure of Sensitive Information to an Unauthorized Actor",
            description: "The application unintentionally exposes sensitive data to unauthorized users, leading to data leaks or privacy violations."
        },
        {
            id: 863,
            name: "Incorrect Authorization",
            description: "Access controls are improperly implemented, allowing users to perform actions they should not be authorized for."
        },
        {
            id: 918,
            name: "Server-Side Request Forgery (SSRF)",
            description: "The application allows attackers to manipulate server-side requests, potentially exposing internal services or accessing restricted resources."
        },
        {
            id: 119,
            name: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            description: "Memory operations are not properly restricted, leading to buffer overflows, crashes, or arbitrary code execution."
        },
        {
            id: 476,
            name: "NULL Pointer Dereference",
            description: "The application attempts to access memory through a null pointer, leading to crashes or denial-of-service conditions."
        },
        {
            id: 798,
            name: "Use of Hard-coded Credentials",
            description: "The application contains embedded credentials, allowing attackers to easily gain unauthorized access."
        },
        {
            id: 190,
            name: "Integer Overflow or Wraparound",
            description: "Improper handling of integer operations can lead to overflows, resulting in security vulnerabilities such as buffer overflows."
        },
        {
            id: 400,
            name: "Uncontrolled Resource Consumption",
            description: "The application does not properly limit resource usage, leading to denial-of-service conditions due to excessive consumption."
        },
        {
            id: 306,
            name: "Missing Authentication for Critical Function",
            description: "A critical function lacks proper authentication, allowing unauthorized users to perform sensitive operations."
        }
    
] as const;

// This class is for the Security Analysis panel with collapsible sections
export class SecurityAnalysisProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private securityIssues: vscode.TreeItem[] = [];
    private matchedCWEs: vscode.TreeItem[] = [];

    constructor(private generatedCodeProvider: GeneratedCodeProvider) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.securityIssues = [];
        this.matchedCWEs = [];
        this.refresh();
    }

    // Helper function to find matching CWEs based on issue description
    private findMatchingCWEs(issue: string): typeof TOP_CWES[number][] {
        return TOP_CWES.filter(cwe => {
            // Convert both strings to lowercase for case-insensitive comparison
            const issueLower = issue.toLowerCase();
            const cweLower = cwe.name.toLowerCase();
            const descLower = cwe.description.toLowerCase();
            
            // Check if the issue description contains keywords from CWE name or description
            return issueLower.includes(cweLower) || 
                   cweLower.includes(issueLower) ||
                   issueLower.includes(descLower) ||
                   descLower.includes(issueLower);
        });
    }


    updateSecurityAnalysis(issues: string[]): void {
        this.securityIssues = issues.map(issue => {
            const item = new vscode.TreeItem(issue);
            item.iconPath = new vscode.ThemeIcon("warning");
            item.tooltip = `Security issue detected: ${issue}`;
            item.description = 'Click to copy';

            item.command = {
                command: 'extension.copyToClipboard',
                title: 'Copy Code',
                arguments: [issue],
            };

            return item;
        });

        // Find and update matching CWEs for all issues
        const matchedCWEs = new Set(
            issues.flatMap(issue => this.findMatchingCWEs(issue))
        );

        this.matchedCWEs = Array.from(matchedCWEs).map(cwe => {
            const item = new vscode.TreeItem(
                `CWE-${cwe.id}: ${cwe.name}`,
                vscode.TreeItemCollapsibleState.None
            );
            item.tooltip = cwe.description;
            item.description = cwe.description;
            item.iconPath = new vscode.ThemeIcon("alert");
            return item;
        });

        this.refresh();
    }

    // Method to run security analysis on the latest generated code
    async analyzeLatestGeneratedCode(): Promise<void> {
        const code = this.generatedCodeProvider.getLatestGeneratedCode();

        if (code) {
            this.clear(); // Clear previous analysis results
            runCTests(code, this); // Run the C tests and update security issues
        } else {
            vscode.window.showWarningMessage("No code generated to analyze.");
        }
    }

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: vscode.TreeItem): vscode.TreeItem[] {
        if (!element) {
            return [
                new vscode.TreeItem('Security Issues', vscode.TreeItemCollapsibleState.Collapsed),
                new vscode.TreeItem('CWE Details', vscode.TreeItemCollapsibleState.Collapsed),
            ];
        }

        if (element.label === 'Security Issues') {
            if (this.securityIssues.length > 0) {
                return this.securityIssues;
            } else {
                const noIssuesItem = new vscode.TreeItem("No security issues found!");
                noIssuesItem.iconPath = new vscode.ThemeIcon("check");
                return [noIssuesItem];
            }
        }

        if (element.label === 'CWE Details') {
            if (this.matchedCWEs.length > 0) {
                return this.matchedCWEs;
            } else {
                const noCweItem = new vscode.TreeItem("No matching CWEs found.");
                noCweItem.iconPath = new vscode.ThemeIcon("info");
                return [noCweItem];
            }
        }

        return [];
    }
}
