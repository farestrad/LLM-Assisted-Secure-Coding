import * as vscode from 'vscode';
import { runCTests } from './testers/cTester';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { securityCheckToCVE } from './testers/cTester';

// Export the TOP_CWES constant
export const TOP_CWES = [
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

type CVEMappingType = {
    [key: string]: { id: string; description: string }[];
};

export const CVE_MAPPING: CVEMappingType = {
    'BufferOverflowCheck': [
        {
            id: "CVE-2021-1234",
            description: "Buffer overflow in XYZ application allows remote attackers to execute arbitrary code.",
        },
    ],
    'HeapOverflowCheck': [
        {
            id: "CVE-2021-5678",
            description: "Heap overflow in ABC library allows attackers to crash the application.",
        },
    ],
    'PlaintextPasswordCheck': [
        {
            id: "CVE-2021-9101",
            description: "Storing passwords in plaintext in XYZ application leads to unauthorized access.",
        },
    ],
    'RaceConditionCheck': [
        {
            id: "CVE-2021-1122",
            description: "Race condition in ABC service allows attackers to bypass security checks.",
        },
    ],
    'OtherVulnerabilitiesCheck': [
        {
            id: "CVE-2021-3344",
            description: "Generic vulnerability in XYZ application allows various attacks.",
        },
    ],
    'RandomNumberGenerationCheck': [
        {
            id: "CVE-2021-5566",
            description: "Weak random number generation in ABC library leads to predictable values.",
        },
    ],
    'WeakHashingEncryptionCheck': [
        {
            id: "CVE-2021-7788",
            description: "Weak hashing algorithm used in XYZ application allows for hash collisions.",
        },
    ],
    'InfiniteLoopCheck': [
        {
            id: "CVE-2021-9900",
            description: "Infinite loop in ABC service leads to denial of service.",
        },
    ],
    'IntegerFlowCheck': [
        {
            id: "CVE-2021-1235",
            description: "Integer overflow in XYZ application allows for buffer overflow.",
        },
    ],
    'PathTraversalCheck': [
        {
            id: "CVE-2021-6789",
            description: "Path traversal vulnerability in ABC application allows unauthorized file access.",
        },
    ],
} as const;

export class SecurityAnalysisProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private securityIssues: vscode.TreeItem[] = [];
    private matchedCWEs: vscode.TreeItem[] = [];
    private rawIssuesText: string[] = []; // Store raw issue text for sharing
    private isAnalyzing: boolean = false;
    private cveItems: vscode.TreeItem[] = [];

    constructor(private generatedCodeProvider: GeneratedCodeProvider) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.securityIssues = [];
        this.matchedCWEs = [];
        this.rawIssuesText = [];
        this.cveItems = [];
        this.refresh();
    }

    /**
     * Updates the security analysis results with matched issues, CWEs, and CVEs.
     */
    updateSecurityAnalysis(
        issues: string[],
        cveDetails: { id: string; description: string }[],
        matchedCWEs: typeof TOP_CWES[number][]
    ): void {
        // Store raw issues for sharing with the right panel
        this.rawIssuesText = [...issues];

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

        // Use matched CWEs passed from runCTests
        this.matchedCWEs = matchedCWEs.map(cwe => {
            const item = new vscode.TreeItem(
                `CWE-${cwe.id}: ${cwe.name}`,
                vscode.TreeItemCollapsibleState.None
            );
            item.tooltip = cwe.description;
            item.description = cwe.description;
            item.iconPath = new vscode.ThemeIcon("alert");
            return item;
        });

        // Update CVE assignments
        this.updateCveAssignments(cveDetails);
        this.refresh();
        this.isAnalyzing = false;
    }

    private updateCveAssignments(cveDetails: { id: string; description: string }[]): void {
        this.cveItems = cveDetails.map(cve => {
            const item = new vscode.TreeItem(`${cve.id}: ${cve.description}`, vscode.TreeItemCollapsibleState.None);
            item.tooltip = `CVE ID: ${cve.id}\nDescription: ${cve.description}`;
            return item;
        });
    }

    async analyzeLatestGeneratedCode(): Promise<void> {
        const code = this.generatedCodeProvider.getLatestGeneratedCode();

        if (code) {
            this.isAnalyzing = true;
            this.clear();
            runCTests(code, this);
        } else {
            vscode.window.showWarningMessage("No code generated to analyze.");
        }
    }

    async analyzeCode(code: string): Promise<void> {
        if (code) {
            this.isAnalyzing = true;
            this.clear();
            runCTests(code, this);
        } else {
            vscode.window.showWarningMessage("No code provided to analyze.");
        }
    }

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: vscode.TreeItem): vscode.ProviderResult<vscode.TreeItem[]> {
        if (!element) {
            return [
                new vscode.TreeItem('Security Issues', vscode.TreeItemCollapsibleState.Expanded),
                new vscode.TreeItem('CWE Details', vscode.TreeItemCollapsibleState.Expanded),
                new vscode.TreeItem('CVE Assignments', vscode.TreeItemCollapsibleState.Expanded),
            ];
        }

        if (element.label === 'Security Issues') {
            if (this.isAnalyzing) {
                const analyzingItem = new vscode.TreeItem("Analyzing code...");
                analyzingItem.iconPath = new vscode.ThemeIcon("loading~spin");
                return [analyzingItem];
            } else if (this.securityIssues.length > 0) {
                return this.securityIssues;
            } else {
                return [new vscode.TreeItem("No security issues found!")];
            }
        }

        if (element.label === 'CWE Details') {
            if (this.isAnalyzing) {
                const analyzingItem = new vscode.TreeItem("Analyzing code...");
                analyzingItem.iconPath = new vscode.ThemeIcon("loading~spin");
                return [analyzingItem];
            } else if (this.matchedCWEs.length > 0) {
                return this.matchedCWEs;
            } else {
                return [new vscode.TreeItem("No matching CWEs found.")];
            }
        }

        if (element.label === 'CVE Assignments') {
            if (this.cveItems.length > 0) {
                return this.cveItems;
            } else {
                return [new vscode.TreeItem("No CVEs found.")];
            }
        }

        return [];
    }
}
