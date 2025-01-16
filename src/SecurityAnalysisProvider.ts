import * as vscode from 'vscode';
import { runCTests } from './testers/cTester';
import { GeneratedCodeProvider } from './generatedCodeProvider';

// This class is for the Security Analysis panel with collapsible sections
export class SecurityAnalysisProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private securityIssues: vscode.TreeItem[] = [];
    private cveDetails: vscode.TreeItem[] = [];

    constructor(private generatedCodeProvider: GeneratedCodeProvider) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.securityIssues = [];
        this.cveDetails = [];
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

    // Updates security issues (e.g., from C tests)
    updateSecurityAnalysis(issues: string[]): void {
        this.securityIssues = issues.map(issue => {
            const item = new vscode.TreeItem(issue);
            item.iconPath = new vscode.ThemeIcon("warning");
            item.tooltip = `Security issue detected: ${issue}`;
            item.description = 'Click to copy'; // Add description to prompt the user

            // Command to copy the issue text to clipboard
            item.command = {
                command: 'extension.copyToClipboard', // Assumes this command is registered in extension.ts
                title: 'Copy Code',
                arguments: [issue], // Pass the issue text as the argument
            };

            return item;
        });
        this.refresh();
    }

    // Updates CVE details (e.g., fetched from the CVE database)
    updateCveDetails(cveDetails: { id: string; description: string }[]): void {
        this.cveDetails = cveDetails.map(cve => {
            const item = new vscode.TreeItem(cve.id, vscode.TreeItemCollapsibleState.None);
            item.tooltip = cve.description;
            item.description = cve.description;
            item.iconPath = new vscode.ThemeIcon("info");

            return item;
        });
        this.refresh();
    }

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    // Collapsible structure for Security Issues and CVE Details
    getChildren(element?: vscode.TreeItem): vscode.TreeItem[] {
        if (!element) {
            // Root level: Return two collapsible sections
            return [
                new vscode.TreeItem('Security Issues', vscode.TreeItemCollapsibleState.Collapsed),
                new vscode.TreeItem('CVE Details', vscode.TreeItemCollapsibleState.Collapsed),
            ];
        }

        // If "Security Issues" is expanded, return the issues
        if (element.label === 'Security Issues') {
            if (this.securityIssues.length > 0) {
                return this.securityIssues;
            } else {
                const noIssuesItem = new vscode.TreeItem("No security issues found!");
                noIssuesItem.iconPath = new vscode.ThemeIcon("check");
                return [noIssuesItem];
            }
        }

        // If "CVE Details" is expanded, return the CVEs
        if (element.label === 'CVE Details') {
            if (this.cveDetails.length > 0) {
                return this.cveDetails;
            } else {
                const noCveItem = new vscode.TreeItem("No CVE details available.");
                noCveItem.iconPath = new vscode.ThemeIcon("info");
                return [noCveItem];
            }
        }

        return [];
    }
}
