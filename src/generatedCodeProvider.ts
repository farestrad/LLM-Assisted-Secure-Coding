import * as vscode from 'vscode';

export class GeneratedCodeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private generatedCode: vscode.TreeItem[] = [];

    // Refresh the view
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    // Update the sidebar with formatted code
    updateGeneratedCode(code: string, language: string = 'plaintext'): void {
        const markdownCode = new vscode.MarkdownString();
        markdownCode.appendCodeblock(code, language);  // Syntax highlighting for tooltip

        // Show part of the code in the label (truncated if needed)
        const truncatedCode = code.length > 50 ? code.substring(0, 47) + '...' : code;

        const treeItem = new vscode.TreeItem(truncatedCode);  // Label shows part of the code
        treeItem.tooltip = markdownCode;  // Full code with syntax highlighting in tooltip
        treeItem.description = 'Click to copy';  // Optional description

        // Command to copy the full code
        treeItem.command = {
            command: 'extension.copyToClipboard',  // Command to copy to clipboard
            title: 'Copy Code',
            arguments: [code],  // Pass the full generated code as an argument
        };

        this.generatedCode = [treeItem];  // Update with new TreeItem
        this.refresh();  // Refresh the TreeView
    }

    // Get the TreeItem (for displaying in the TreeView)
    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    // Get the list of children (only one in this case, the generated code)
    getChildren(): vscode.TreeItem[] {
        return this.generatedCode;
    }
}
