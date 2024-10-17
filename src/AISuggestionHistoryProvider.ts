import * as vscode from 'vscode';

// Class to represent individual AI suggestions
export class AISuggestion {   // <-- Add `export` here
    public label: string;
    public status: 'pending' | 'accepted' | 'rejected';
    public originalCode: string;
    public suggestion: string;

    constructor(suggestion: string, originalCode: string) {
        this.label = suggestion.length > 50 ? suggestion.substring(0, 47) + '...' : suggestion;
        this.status = 'pending'; // Default status is "pending"
        this.suggestion = suggestion;
        this.originalCode = originalCode;
    }

    // Return a TreeItem representing this suggestion in the UI
    getTreeItem(): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(`${this.label} (${this.status})`, vscode.TreeItemCollapsibleState.None);
        treeItem.tooltip = this.suggestion;

        // Add context value to enable right-click actions (Accept, Reject, Undo)
        treeItem.contextValue = 'suggestion'; 

        return treeItem;
    }
}

export class AISuggestionHistoryProvider implements vscode.TreeDataProvider<AISuggestion> {
    private _onDidChangeTreeData: vscode.EventEmitter<AISuggestion | undefined | void> = new vscode.EventEmitter<AISuggestion | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<AISuggestion | undefined | void> = this._onDidChangeTreeData.event;

    // Internal list of suggestions
    private suggestions: AISuggestion[] = [];

    // Refresh the view when the data changes
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    // Add a new AI suggestion to the history
    addAISuggestion(suggestion: string, originalCode: string): void {
        const newSuggestion = new AISuggestion(suggestion, originalCode);
        this.suggestions.push(newSuggestion);
        this.refresh();
    }

    // Update the status of an AI suggestion (accept/reject)
    updateAISuggestionStatus(id: number, status: 'accepted' | 'rejected'): void {
        if (id < this.suggestions.length) {
            this.suggestions[id].status = status;
            this.refresh();
        }
    }

    // Undo an AI suggestion (revert to original code and mark it as pending)
    undoAISuggestion(id: number): string | null {
        if (id < this.suggestions.length) {
            this.suggestions[id].status = 'pending';
            this.refresh();
            return this.suggestions[id].originalCode;
        }
        return null;
    }

    // Return TreeItem for each AI suggestion
    getTreeItem(element: AISuggestion): vscode.TreeItem {
        return element.getTreeItem();
    }

    // Return the list of suggestions as TreeItems for display in the view
    getChildren(): AISuggestion[] {
        return this.suggestions;
    }
}
