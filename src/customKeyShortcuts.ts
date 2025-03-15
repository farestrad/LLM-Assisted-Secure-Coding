import * as vscode from 'vscode';
import { AISuggestionHistoryProvider } from './AISuggestionHistoryProvider';

interface CustomShortcut {
    command: string;
    keybinding: string;
    title: string;
    when?: string;
}

// Define all shortcuts based on the package.json contributes section
const customShortcuts: CustomShortcut[] = [
    { command: 'codeLlama.runCodeLlama', keybinding: 'ctrl+alt+l', title: 'Run Code Llama', when: 'editorTextFocus' },
    { command: 'extension.runSecurityAnalysis', keybinding: 'ctrl+alt+r', title: 'Run Security Analysis', when: 'editorTextFocus' },
    { command: 'extension.analyzeHighlightedCode', keybinding: 'ctrl+alt+h', title: 'Analyze Highlighted Code', when: 'editorTextFocus && editorHasSelection' },
    { command: 'extension.testSecurityAnalysis', keybinding: 'ctrl+alt+t', title: 'Test Security Analysis', when: 'editorTextFocus' },
    { command: 'codeLlama.generateCode', keybinding: 'ctrl+alt+g', title: 'Generate Code', when: 'editorTextFocus' },
    { command: 'extension.acceptAISuggestion', keybinding: 'ctrl+alt+1', title: 'Accept AI Suggestion', when: 'editorTextFocus' },
    { command: 'extension.rejectAISuggestion', keybinding: 'ctrl+alt+2', title: 'Reject AI Suggestion', when: 'editorTextFocus' },
    { command: 'extension.triggerAISuggestion', keybinding: 'ctrl+alt+s', title: 'Trigger AI Suggestion', when: 'editorTextFocus' },
    { command: 'extension.acceptCodeChanges', keybinding: 'ctrl+alt+a', title: 'Accept Code Changes', when: 'editorTextFocus' },
    { command: 'extension.toggleAssistantSidebar', keybinding: 'ctrl+alt+d', title: 'Toggle Assistant Sidebar', when: 'editorTextFocus' },
    { command: 'extension.fetchCveDetails', keybinding: 'ctrl+alt+c', title: 'Fetch CVE Details', when: 'editorTextFocus' },
    { command: 'extension.safescript.showRightPanel', keybinding: 'ctrl+alt+p', title: 'Show SafeScript Panel', when: 'editorTextFocus' },
    { command: 'extension.copyToClipboard', keybinding: 'ctrl+alt+y', title: 'Copy Generated Code', when: 'editorTextFocus' },
    { command: 'extension.undoAISuggestion', keybinding: 'ctrl+alt+z', title: 'Undo AI Suggestion', when: 'editorTextFocus' },
    { command: 'extension.acceptGeneratedCode', keybinding: 'ctrl+alt+enter', title: 'Accept Generated Code', when: 'editorTextFocus' }
];

// Represents a class that manages custom key shortcuts for a VSCode extension.
export class CustomKeyShortcuts {
    // Creates an instance of CustomKeyShortcuts.
    constructor(private context: vscode.ExtensionContext, private historyProvider: AISuggestionHistoryProvider) {}
    
    // Activates the custom key shortcuts by registering commands and setting their keybindings.
    public activate() {
        customShortcuts.forEach(shortcut => {
            const disposable = vscode.commands.registerCommand(shortcut.command, (suggestionId?: number) => {
                // Handle suggestion status updates
                if (shortcut.command === 'extension.acceptAISuggestion' && suggestionId !== undefined) {
                    this.historyProvider.updateAISuggestionStatus(suggestionId, 'accepted');
                }
                else if (shortcut.command === 'extension.rejectAISuggestion' && suggestionId !== undefined) {
                    this.historyProvider.updateAISuggestionStatus(suggestionId, 'rejected');
                }
                
                vscode.window.showInformationMessage(`Command ${shortcut.title} triggered!`);
            });
            
            this.context.subscriptions.push(disposable);
            
            // Register custom keybinding context
            if (shortcut.when) {
                vscode.commands.executeCommand('setContext', `keybinding.${shortcut.command}`, true);
            }
        });
        
        // Register key bindings in VSCode
        this.registerKeybindings();
    }
    
    // Register keybindings through the VSCode API
    private registerKeybindings() {
        // VS Code doesn't allow programmatic registration of keybindings via API
        // This would need to be done in package.json or through user settings
        // This is a placeholder for documentation purposes
        vscode.window.showInformationMessage('Custom shortcuts activated. Keybindings are defined in package.json');
    }
    
    // Creates a keybinding configuration object for package.json
    public static generateKeybindingConfiguration(): any {
        return {
            keybindings: customShortcuts.map(shortcut => ({
                command: shortcut.command,
                key: shortcut.keybinding,
                when: shortcut.when || 'editorTextFocus'
            }))
        };
    }
    
    // Deactivates the custom key shortcuts.
    public deactivate() {
        // Clean up context keys
        customShortcuts.forEach(shortcut => {
            vscode.commands.executeCommand('setContext', `keybinding.${shortcut.command}`, false);
        });
        
        vscode.window.showInformationMessage('Custom shortcuts deactivated.');
    }
}