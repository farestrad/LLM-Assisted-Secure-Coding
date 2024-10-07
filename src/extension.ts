import * as vscode from 'vscode';
import fetch from 'node-fetch';

export function activate(context: vscode.ExtensionContext) {
    let disposable = vscode.commands.registerCommand('codeLlama.runCodeLlama', async () => {
        // Create an output channel
        const outputChannel = vscode.window.createOutputChannel("Code Llama Output");

        // Show the output channel window
        outputChannel.show(true);

        // Get the active text editor
        const editor = vscode.window.activeTextEditor;

        if (editor) {
            // Get the selected text
            const selection = editor.selection;
            const selectedText = editor.document.getText(selection);

            if (!selectedText) {
                vscode.window.showErrorMessage('Please select the line you want to check.');
                return;
            }

            outputChannel.appendLine('Checking code for Vulnerabilities...');

            try {
                // Call the Code Llama API with streaming enabled
                const response = await fetch('http://167.99.179.121:11434/api/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        model: 'llama3',
                        prompt: selectedText,
                        stream: true,
                    }),
                });

                if (!response.ok) {
                    throw new Error('Oops our bad.. try again!');
                }

                // Use Node.js stream API instead of getReader
                const stream = response.body as unknown as NodeJS.ReadableStream;

                let partialResponse = '';

                stream.on('data', (chunk) => {
                    // Convert chunk to a string and parse it as JSON
                    const jsonChunk = JSON.parse(chunk.toString());
                    
                    // Extract the 'response' field from the JSON (or handle other fields if needed)
                    const outputText = jsonChunk.response || 'No valid response found';

                    // Append the parsed response to the output channel
                    partialResponse += outputText;
                    outputChannel.append(outputText); // Update the output progressively
                });

                stream.on('end', () => {
                    // Show the final accumulated response
                    outputChannel.appendLine('\n\nDone!');
                });

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