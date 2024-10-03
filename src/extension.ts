import * as vscode from 'vscode';

export async function activate(context: vscode.ExtensionContext) {
    const fetch = (await import('node-fetch')).default;

    let disposable = vscode.commands.registerCommand('codeLlama.runCodeLlama', async () => {
        // Create an output channel
        const outputChannel = vscode.window.createOutputChannel("Code Llama Output");
        outputChannel.show(true);

        const editor = vscode.window.activeTextEditor;

        if (editor) {
            const selection = editor.selection;
            const selectedText = editor.document.getText(selection);

            if (!selectedText) {
                vscode.window.showErrorMessage('No text selected. Please select a prompt.');
                return;
            }

            outputChannel.appendLine('Sending code to Code Llama with streaming...');

            try {
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
                    throw new Error('Failed to fetch response from server');
                }

                const stream = response.body as unknown as NodeJS.ReadableStream;

                let partialResponse = '';

                stream.on('data', (chunk) => {
                    const jsonChunk = JSON.parse(chunk.toString());
                    const outputText = jsonChunk.response || 'No valid response found';
                    partialResponse += outputText;
                    outputChannel.append(outputText);
                });

                stream.on('end', () => {
                    outputChannel.appendLine('\n\nStreaming complete.');
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
