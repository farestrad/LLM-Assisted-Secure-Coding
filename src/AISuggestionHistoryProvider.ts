import * as vscode from 'vscode';

// Class to represent individual AI suggestions
export class AISuggestion {
    public label: string;
    public status: 'pending' | 'accepted' | 'rejected';
    public originalCode: string;
    public suggestion: string;
    public id: number;  // Unique ID for each suggestion
    
    constructor(id: number, suggestion: string, originalCode: string) {
        this.id = id;  // Unique identifier for each suggestion
        
        // Sanitize and truncate code for the label
        const sanitizedCode = suggestion.replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim();
        this.label = sanitizedCode.length > 50 ? sanitizedCode.substring(0, 47) + '...' : sanitizedCode;
        
        this.status = 'pending'; // Default status is "pending"
        this.suggestion = suggestion;
        this.originalCode = originalCode;
    }
    
    // Return a TreeItem representing this suggestion in the UI
    getTreeItem(): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(`${this.label} (${this.status})`, vscode.TreeItemCollapsibleState.None);
        
        // Use markdown for syntax highlighting in tooltip
        const markdownTooltip = new vscode.MarkdownString('```c\n' + this.suggestion + '\n```');
        markdownTooltip.isTrusted = true;
        treeItem.tooltip = markdownTooltip;
        
        // Add unique ID and context value to enable right-click actions (Accept, Reject, Undo, Copy)
        treeItem.id = this.id.toString();  // Unique ID used for the command
        treeItem.contextValue = 'suggestion';  // Enable right-click actions
        
        // Add command for changing status when clicked
        treeItem.command = {
            command: 'extension.toggleSuggestionStatus',  // Command to toggle status
            title: 'Toggle Status',
            arguments: [this],  // Pass the current suggestion as an argument
        };
        
        return treeItem;
    }
}

export class AISuggestionHistoryProvider implements vscode.TreeDataProvider<AISuggestion> {
    private _onDidChangeTreeData: vscode.EventEmitter<AISuggestion | undefined | void> = new vscode.EventEmitter<AISuggestion | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<AISuggestion | undefined | void> = this._onDidChangeTreeData.event;
    
    // Internal list of suggestions
    private suggestions: AISuggestion[] = [];
    private nextId = 1;  // Counter for unique suggestion IDs
    
    // Refresh the view when the data changes
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }
    
    // Add a new AI suggestion to the history
    addAISuggestion(suggestion: string, originalCode: string): void {
        const newSuggestion = new AISuggestion(this.nextId++, suggestion, originalCode);  // Unique ID for each new suggestion
        this.suggestions.push(newSuggestion);
        this.refresh();
    }
    
    // Update the status of an AI suggestion (accept/reject)
    updateAISuggestionStatus(id: number, status: 'accepted' | 'rejected'): void {
        const suggestion = this.suggestions.find(s => s.id === id);
        if (suggestion) {
            suggestion.status = status;
            this.refresh();
        }
    }
    
    // Return TreeItem for each AI suggestion
    getTreeItem(element: AISuggestion): vscode.TreeItem {
        return element.getTreeItem();
    }
    
    // Return the list of suggestions as TreeItems for display in the view
    getChildren(element?: AISuggestion): vscode.ProviderResult<AISuggestion[]> {
        return this.suggestions;
    }
    
    // Get suggestion by ID
    getSuggestionById(id: number): AISuggestion | undefined {
        return this.suggestions.find(s => s.id === id);
    }
}

// Now, add the extension activation function that registers the copy command
export function activate(context: vscode.ExtensionContext) {
    // Create the AI suggestion provider
    const aiSuggestionProvider = new AISuggestionHistoryProvider();
    
    // Register the provider
    const aiSuggestionView = vscode.window.createTreeView('aiSuggestions', {
        treeDataProvider: aiSuggestionProvider,
        showCollapseAll: false
    });
    
    // Register the copy command
    const copyCommand = vscode.commands.registerCommand('extension.copySuggestion', (suggestionId: number) => {
        const suggestion = aiSuggestionProvider.getSuggestionById(suggestionId);
        if (suggestion) {
            vscode.env.clipboard.writeText(suggestion.suggestion);
            vscode.window.showInformationMessage('Copied to clipboard');
        }
    });
    
    // Register other commands (toggle status, etc.)
    const toggleStatusCommand = vscode.commands.registerCommand('extension.toggleSuggestionStatus', (suggestion: AISuggestion) => {
        // Toggle between pending, accepted, rejected
        const newStatus = suggestion.status === 'pending' ? 'accepted' : 
                         suggestion.status === 'accepted' ? 'rejected' : 'pending';
        aiSuggestionProvider.updateAISuggestionStatus(suggestion.id, newStatus as 'accepted' | 'rejected');
    });
    
    // Add to context subscriptions
    context.subscriptions.push(aiSuggestionView, copyCommand, toggleStatusCommand);
}