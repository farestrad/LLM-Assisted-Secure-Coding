import * as vscode from 'vscode';

interface CustomShortcut {
    command: string;
    keybinding: string;
}

const customShortcuts: CustomShortcut[] = [
    { command: 'extension.triggerAISuggestion', keybinding: 'ctrl+alt+s' },
    { command: 'extension.acceptCodeChanges', keybinding: 'ctrl+alt+a' },
    { command: 'extension.toggleAssistantSidebar', keybinding: 'ctrl+alt+d' }
];

// Represents a class that manages custom key shortcuts for a VSCode extension.
export class CustomKeyShortcuts {
    // Creates an instance of CustomKeyShortcuts.
    constructor(private context: vscode.ExtensionContext) {}

    // Activates the custom key shortcuts by registering commands and setting their keybindings.
    public activate() {
        customShortcuts.forEach(shortcut => {
            const disposable = vscode.commands.registerCommand(shortcut.command, () => {
                vscode.window.showInformationMessage(`Command ${shortcut.command} triggered!`);
            });

            this.context.subscriptions.push(disposable);

            vscode.commands.executeCommand('setContext', `keybinding.${shortcut.command}`, shortcut.keybinding);
        });
    }

    // Deactivates the custom key shortcuts.
    public deactivate() {}
}