import * as vscode from 'vscode';
import { runCTests } from './testers/cTester';
import { GeneratedCodeProvider } from './generatedCodeProvider';

// Define the CWE type for better structure
export type CWE = {
    id: number;
    name: string;
    description: string;
};

// Complete list of CWEs referenced in the mappings
export const CWE_DATABASE: { [id: number]: CWE } = {
    // Input Validation
    20: {
        id: 20,
        name: "Improper Input Validation",
        description: "The application does not validate or incorrectly validates input that can affect the control flow or data flow of a program."
    },
    
    // Path Issues
    22: {
        id: 22,
        name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        description: "The application does not properly neutralize special elements within a pathname, allowing attackers to escape outside of the restricted directory."
    },
    23: {
        id: 23,
        name: "Relative Path Traversal",
        description: "The application uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize relative path sequences."
    },
    36: {
        id: 36,
        name: "Absolute Path Traversal",
        description: "The application uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize absolute path sequences."
    },
    73: {
        id: 73,
        name: "External Control of File Name or Path",
        description: "The application allows user input to control or influence paths or file names used in filesystem operations."
    },
    
    // Injection
    78: {
        id: 78,
        name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        description: "The application constructs all or part of an OS command using externally-influenced input without neutralizing special elements."
    },
    89: {
        id: 89,
        name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        description: "The application constructs SQL commands using input from an upstream component without neutralizing special elements."
    },
    94: {
        id: 94,
        name: "Improper Control of Generation of Code ('Code Injection')",
        description: "The application constructs all or part of a code segment using externally-influenced input without properly neutralizing."
    },
    
    // Buffer Issues
    119: {
        id: 119,
        name: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        description: "The application performs operations on a memory buffer, but can read from or write to a memory location outside of the intended boundary."
    },
    120: {
        id: 120,
        name: "Buffer Copy without Checking Size of Input",
        description: "The application copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer."
    },
    122: {
        id: 122,
        name: "Heap-based Buffer Overflow",
        description: "A heap overflow condition is a type of buffer overflow where the buffer that overflows is allocated in the heap portion of memory."
    },
    125: {
        id: 125,
        name: "Out-of-bounds Read",
        description: "The application reads data past the end, or before the beginning, of the intended buffer."
    },
    
    // Credentials
    256: {
        id: 256,
        name: "Plaintext Storage of a Password",
        description: "Storing a password in plaintext may result in a system compromise."
    },
    319: {
        id: 319,
        name: "Cleartext Transmission of Sensitive Information",
        description: "The application transmits sensitive data in cleartext in a communication channel."
    },
    
    // Cryptographic Issues
    327: {
        id: 327,
        name: "Use of a Broken or Risky Cryptographic Algorithm",
        description: "The application uses a broken or risky cryptographic algorithm for sensitive data."
    },
    328: {
        id: 328,
        name: "Use of Weak Hash",
        description: "The application uses a hash algorithm with known weaknesses."
    },
    330: {
        id: 330,
        name: "Use of Insufficiently Random Values",
        description: "The application uses insufficiently random values, causing a protection mechanism to be compromised."
    },
    338: {
        id: 338,
        name: "Use of Cryptographically Weak Pseudo-Random Number Generator",
        description: "The application uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG is cryptographically weak."
    },
    759: {
        id: 759,
        name: "Use of a One-Way Hash without a Salt",
        description: "The application uses a one-way hash without a salt, making it vulnerable to rainbow table attacks."
    },
    
    // Race Conditions
    362: {
        id: 362,
        name: "Race Condition",
        description: "The application has multiple threads of execution and the order of operations can affect the correctness of the result."
    },
    366: {
        id: 366,
        name: "Race Condition within a Thread",
        description: "The application contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource."
    },
    367: {
        id: 367,
        name: "Time-of-check Time-of-use (TOCTOU) Race Condition",
        description: "The application checks the state of a resource before using it, but the resource's state can change between the check and the use."
    },
    
    // Resource Management
    400: {
        id: 400,
        name: "Uncontrolled Resource Consumption",
        description: "The application does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed."
    },
    415: {
        id: 415,
        name: "Double Free",
        description: "The application calls free() twice on the same memory address, potentially leading to memory corruption."
    },
    416: {
        id: 416,
        name: "Use After Free",
        description: "The application references memory after it has been freed, which can lead to program crashes or execution of arbitrary code."
    },
    476: {
        id: 476,
        name: "NULL Pointer Dereference",
        description: "The application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash."
    },
    590: {
        id: 590,
        name: "Free of Memory not on the Heap",
        description: "The application calls free() on a pointer to memory that was not allocated on the heap."
    },
    680: {
        id: 680, 
        name: "Integer Overflow to Buffer Overflow",
        description: "The application performs a calculation to determine how much memory to allocate, but an integer overflow can lead to allocating less memory than expected."
    },
    761: {
        id: 761,
        name: "Free of Pointer not at Start of Buffer",
        description: "The application calls free() on a pointer that was not returned from malloc() or similar allocation functions."
    },
    787: {
        id: 787,
        name: "Out-of-bounds Write",
        description: "The application writes data past the end, or before the beginning, of the intended buffer."
    },
    
    // Loop Issues
    835: {
        id: 835,
        name: "Loop with Unreachable Exit Condition",
        description: "The application contains a loop with an exit condition that cannot be reached, i.e., an infinite loop."
    },
    
    // Integer Issues
    190: {
        id: 190,
        name: "Integer Overflow or Wraparound",
        description: "The application performs a calculation that can produce an integer overflow or wraparound, when the resulting value is used in a security-critical context."
    },
    191: {
        id: 191,
        name: "Integer Underflow",
        description: "The application subtracts a value from a numeric variable, but the result is less than the variable's minimum allowable value."
    }
};

// Export TOP_CWES based on the database for backward compatibility
export const TOP_CWES = Object.values(CWE_DATABASE);

// Mapping of security checks to relevant CWEs
export const securityCheckToCWE: { [key: string]: number[] } = {
    'BufferOverflowCheck': [120, 119, 125, 787], // Buffer Copy without Checking Size, Improper Restriction of Operations within Bounds, Out-of-bounds Read, Out-of-bounds Write
    'HeapOverflowCheck': [122, 590, 761], // Heap-based Buffer Overflow, Free of Memory not on the Heap, Free of Pointer not at Start of Buffer
    'PlaintextPasswordCheck': [256, 319], // Plaintext Storage of a Password, Cleartext Transmission of Sensitive Information
    'RaceConditionCheck': [362, 366, 367], // Race Condition, Race Condition within a Thread, Time-of-check Time-of-use Race Condition
    'OtherVulnerabilitiesCheck': [78, 89, 94, 22], // OS Command Injection, SQL Injection, Code Injection, Path Traversal
    'RandomNumberGenerationCheck': [330, 338], // Use of Insufficiently Random Values, Use of Cryptographically Weak PRNG
    'WeakHashingEncryptionCheck': [327, 328, 759], // Use of a Broken/Risky Cryptographic Algorithm, Reversible One-Way Hash, Use of a One-Way Hash without a Salt
    'InfiniteLoopCheck': [400, 835], // Uncontrolled Resource Consumption, Loop with Unreachable Exit Condition
    'IntegerFlowCheck': [190, 191, 680], // Integer Overflow/Wraparound, Integer Underflow, Integer Overflow to Buffer Overflow
    'PathTraversalCheck': [22, 23, 36, 73], // Path Traversal, Relative Path Traversal, Absolute Path Traversal, External Control of File Name
    'FloatingInMemoryCheck': [416, 415, 476] // Use After Free, Double Free, NULL Pointer Dereference
};

// Helper function to get CWE objects for a security check
export function getCWEsForSecurityCheck(checkName: string): CWE[] {
    const cweIds = securityCheckToCWE[checkName] || [];
    return cweIds.map(id => CWE_DATABASE[id]).filter(cwe => cwe !== undefined);
}

// Single, unified mapping of CVEs to security checks
export const CVE_MAPPING: { [key: string]: { id: string; description: string }[] } = {
    'BufferOverflowCheck': [
        { id: "CVE-2021-1234", description: "Buffer overflow in XYZ application allows remote attackers to execute arbitrary code." },
        { id: "CVE-2019-9999", description: "Stack-based buffer overflow in ABC library allows attackers to execute arbitrary code." }
    ],
    'HeapOverflowCheck': [
        { id: "CVE-2021-5678", description: "Heap overflow in ABC library allows attackers to crash the application." },
        { id: "CVE-2020-8888", description: "Use-after-free vulnerability in XYZ application allows remote attackers to execute arbitrary code." }
    ],
    'PlaintextPasswordCheck': [
        { id: "CVE-2021-9101", description: "Storing passwords in plaintext in XYZ application leads to unauthorized access." },
        { id: "CVE-2018-7777", description: "Credentials transmitted in cleartext in ABC service, allowing attackers to intercept sensitive information." }
    ],
    'RaceConditionCheck': [
        { id: "CVE-2021-1122", description: "Race condition in ABC service allows attackers to bypass security checks." },
        { id: "CVE-2017-5555", description: "TOCTOU vulnerability in file handling allows attackers to manipulate privileged operations." }
    ],
    'OtherVulnerabilitiesCheck': [
        { id: "CVE-2021-3344", description: "Command injection vulnerability in XYZ application allows attackers to execute arbitrary OS commands." },
        { id: "CVE-2020-4321", description: "SQL injection in ABC service allows attackers to access sensitive database information." }
    ],
    'RandomNumberGenerationCheck': [
        { id: "CVE-2021-5566", description: "Weak random number generation in ABC library leads to predictable values." },
        { id: "CVE-2019-1212", description: "Insufficient entropy in PRNG implementation allows attackers to predict generated values." }
    ],
    'WeakHashingEncryptionCheck': [
        { id: "CVE-2021-7788", description: "Weak hashing algorithm used in XYZ application allows for hash collisions." },
        { id: "CVE-2018-9876", description: "Use of MD5 for password storage in ABC service makes password hashes vulnerable to cracking." }
    ],
    'InfiniteLoopCheck': [
        { id: "CVE-2021-9900", description: "Infinite loop in ABC service leads to denial of service." },
        { id: "CVE-2020-5544", description: "Resource exhaustion through uncontrolled loop in XYZ application allows for DoS attacks." }
    ],
    'IntegerFlowCheck': [
        { id: "CVE-2021-1235", description: "Integer overflow in XYZ application allows for buffer overflow." },
        { id: "CVE-2019-8765", description: "Integer underflow in memory allocation leads to exploitable condition in ABC library." }
    ],
    'PathTraversalCheck': [
        { id: "CVE-2021-6789", description: "Path traversal vulnerability in ABC application allows unauthorized file access." },
        { id: "CVE-2018-3311", description: "Directory traversal in file upload functionality allows attackers to access sensitive files." }
    ],
    'FloatingInMemoryCheck': [
        { id: "CVE-2021-4455", description: "Use-after-free vulnerability in memory management allows for arbitrary code execution." },
        { id: "CVE-2019-6545", description: "Double-free vulnerability in XYZ application leads to memory corruption." }
    ]
};














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
        cveDetails: { id: string; description: string }[] = [],
        matchedCWEs: CWE[] = []
    ): void {
        // Store raw issues for sharing with the right panel
        this.rawIssuesText = [...issues];

        // Format security issues
        this.securityIssues = issues.map(issue => {
            // Remove the check name if present (e.g., "Message (CheckName)")
            const formattedIssue = issue.replace(/\s+\([A-Za-z]+Check\)$/, '');
            
            const item = new vscode.TreeItem(formattedIssue);
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

        // Format CWE details
        this.matchedCWEs = matchedCWEs.map(cwe => {
            const item = new vscode.TreeItem(
                `CWE-${cwe.id}: ${cwe.name}`,
                vscode.TreeItemCollapsibleState.None
            );
            item.tooltip = cwe.description;
            
            // Truncate long descriptions for display
            let description = cwe.description;
            if (description.length > 80) {
                description = description.substring(0, 77) + '...';
            }
            item.description = description;
            
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
            const item = new vscode.TreeItem(
                `${cve.id}`,
                vscode.TreeItemCollapsibleState.None
            );
            
            item.tooltip = `${cve.id}: ${cve.description}`;
            
            // Truncate long descriptions for display
            let description = cve.description;
            if (description.length > 80) {
                description = description.substring(0, 77) + '...';
            }
            item.description = description;
            
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

    /**
     * Get raw security issues text for external components
     */
    getRawSecurityIssues(): string[] {
        return this.rawIssuesText;
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