import * as vscode from 'vscode';
import fetch from 'node-fetch';

export function activate(context: vscode.ExtensionContext) {
    let disposable = vscode.commands.registerCommand('codeLlama.runCodeLlama', async () => {
        // Get the active text editor
        const editor = vscode.window.activeTextEditor;

        if (editor) {
            // Get the selected text or provide a default prompt
            const selection = editor.selection;
            const selectedText = editor.document.getText(selection);

            // Log the selected text to ensure it's correct
            console.log('Selected Text:', selectedText);

            // Handle case where no text is selected
            if (!selectedText) {
                vscode.window.showErrorMessage('No text selected. Please select a prompt.');
                return;
            }

            vscode.window.showInformationMessage('Sending code to Code Llama...');

            try {
                // Call the Code Llama API
                const response = await fetch('http://167.99.179.121:11434/api/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        model: 'llama3',
                        prompt: selectedText,  // Ensure selectedText is sent
                        stream: false,
                    }),
                });

                if (!response.ok) {
                    throw new Error('Failed to fetch response from server');
                }

                const result = await response.json();

            // Extract the 'response' field from the result
    const outputText = result.response || "No valid response found.";

    // Show the output in an information message
    vscode.window.showInformationMessage(`Code Llama Output: ${outputText}`);
} catch (error: any) {
    vscode.window.showErrorMessage(`Error: ${(error as Error).message}`);
}

        } else {
            vscode.window.showErrorMessage('No active editor found.');
        }
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
