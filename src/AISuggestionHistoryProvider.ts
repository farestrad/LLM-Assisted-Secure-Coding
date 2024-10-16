import * as vscode from 'vscode';

interface AISuggestion {
    id: number;
    suggestion: string;
    status: 'pending' | 'accepted' | 'rejected';
    originalCode: string;  // Keep track of the original code to handle undo
}

export class AISuggestionHistoryProvider implements vscode.TreeDataProvider<vscode.TreeItem> {

    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private suggestionLog: AISuggestion[] = [];
    private nextId = 1;

    // Refresh the view when data changes
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    // Add a new suggestion to the history log
    addAISuggestion(suggestion: string, originalCode: string): void {
        this.suggestionLog.push({
            id: this.nextId++,
            suggestion,
            status: 'pending',
            originalCode
        });
        this.refresh();
    }

    // Update the status of a suggestion (Accept/Reject/Undo)
    updateAISuggestionStatus(id: number, status: 'accepted' | 'rejected'): void {
        const suggestion = this.suggestionLog.find(s => s.id === id);
        if (suggestion) {
            suggestion.status = status;
            this.refresh();
        }
    }

    // Undo a suggestion and revert the original code
    undoAISuggestion(id: number): string | null {
        const suggestion = this.suggestionLog.find(s => s.id === id);
        if (suggestion && suggestion.status === 'accepted') {
            suggestion.status = 'pending';
            this.refresh();
            return suggestion.originalCode;
        }
        return null;
    }

    // Return TreeItem for each suggestion
    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    // Return the list of suggestions as TreeItems
    getChildren(): vscode.TreeItem[] {
        return this.suggestionLog.map(suggestion => {
            const treeItem = new vscode.TreeItem(suggestion.suggestion);
            treeItem.description = suggestion.status;
            treeItem.contextValue = 'aiSuggestion';  // Enable right-click actions (Accept, Reject, Undo)
            treeItem.id = suggestion.id.toString();  // Ensure unique IDs
            return treeItem;
        });
    }
}
