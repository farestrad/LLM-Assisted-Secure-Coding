import * as vscode from 'vscode';
import { AISuggestionHistoryProvider, AISuggestion } from './AISuggestionHistoryProvider';  // Import AISuggestion

interface CustomShortcut {
    command: string;
    keybinding: string;
    title: string;
}

const customShortcuts: CustomShortcut[] = [
    { command: 'extension.triggerAISuggestion', keybinding: 'ctrl+alt+s', title: 'trigger AI Suggestion' },
    { command: 'extension.acceptCodeChanges', keybinding: 'ctrl+alt+a', title: 'Accept Code Changes' },
    { command: 'extension.acceptCodeChanges', keybinding: 'ctrl+alt+r', title: 'Reject Code Changes' },
    { command: 'extension.toggleAssistantSidebar', keybinding: 'ctrl+alt+d', title: 'Toggle Assistance Sidebar' }
];

// Represents a class that manages custom key shortcuts for a VSCode extension.
export class CustomKeyShortcuts {
    // Creates an instance of CustomKeyShortcuts.
    constructor(private context: vscode.ExtensionContext, private historyprovider: AISuggestionHistoryProvider) {}

    // Activates the custom key shortcuts by registering commands and setting their keybindings.
    public activate() {
        customShortcuts.forEach(shortcut => {
            const disposable = vscode.commands.registerCommand(shortcut.command, (suggestionId: number) => {
                if (shortcut.command === 'extension.acceptSuggestion') {
                    this.historyprovider.updateAISuggestionStatus(suggestionId, 'accepted');
                }
                else if (shortcut.command === 'extension.rejectSuggestion') {
                    this.historyprovider.updateAISuggestionStatus(suggestionId, 'rejected');
                }
                vscode.window.showInformationMessage(`Command ${shortcut.command} triggered!`);
            });

            this.context.subscriptions.push(disposable);

            vscode.commands.executeCommand('setContext', `keybinding.${shortcut.command}`, shortcut.keybinding);
        });
    }

    // Deactivates the custom key shortcuts.
    public deactivate() {
        vscode.window.showInformationMessage('Custom shortcuts deactivated.');
    }
}