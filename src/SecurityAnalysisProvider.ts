import * as vscode from 'vscode';
import { runCTests } from './testers/cTester';
import { GeneratedCodeProvider } from './generatedCodeProvider';

// This class is for the Security Analysis panel
export class SecurityAnalysisProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private securityIssues: vscode.TreeItem[] = [];

    constructor(private generatedCodeProvider: GeneratedCodeProvider) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.securityIssues = [];
        this.refresh();
    }

    // Method to run security analysis on the latest generated code
    async analyzeLatestGeneratedCode(): Promise<void> {
        // Get the latest generated code directly as a string
        const code = this.generatedCodeProvider.getLatestGeneratedCode();

        if (code) {
            this.clear();  // Clear previous analysis results
            runCTests(code, this);  // Run the C tests and update security issues
        } else {
            vscode.window.showWarningMessage("No code generated to analyze.");
        }
     }

    updateSecurityAnalysis(issues: string[]): void {
        this.securityIssues = issues.map(issue => {
            const item = new vscode.TreeItem(issue);
            item.iconPath = new vscode.ThemeIcon("warning");
            item.tooltip = `Security issue detected: ${issue}`;
            return item;
        });
        this.refresh();
    }

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(): vscode.TreeItem[] {
        if (this.securityIssues.length > 0) {
            return this.securityIssues;
        } else {
            const noIssuesItem = new vscode.TreeItem("No security issues found!");
            noIssuesItem.iconPath = new vscode.ThemeIcon("check");
            return [noIssuesItem];
        }
    }
}
