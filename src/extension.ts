import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';

export function activate(context: vscode.ExtensionContext) {
    // Create an instance of GeneratedCodeProvider to manage sidebar data
    const generatedCodeProvider = new GeneratedCodeProvider();
    
    // Register the provider with the view ID from package.json
    vscode.window.registerTreeDataProvider('codeLlamaGeneratedCodeView', generatedCodeProvider);

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

            outputChannel.appendLine('Generating code with Code Llama...');

            try {
                // Call the Code Llama API with streaming enabled
                const response = await fetch('http://178.128.231.154:11434/api/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        model: 'llama3',
                        prompt: selectedText,
                        stream: true,  // Streaming enabled
                    }),
                });

                if (!response.ok) {
                    throw new Error('Error generating code. Please try again.');
                }

                // Use Node.js stream API to handle streaming
                const stream = response.body as unknown as NodeJS.ReadableStream;
                let partialResponse = '';

                stream.on('data', (chunk) => {
                    const jsonChunk = JSON.parse(chunk.toString());
                
                    if (jsonChunk.response) {
                        const outputText = jsonChunk.response;
                        partialResponse += outputText;
                
                        // Update the output channel
                        outputChannel.append(outputText);
                
                        // Update the sidebar with syntax-highlighted code (e.g., 'python')
                        generatedCodeProvider.updateGeneratedCode(partialResponse, 'python');  // Adjust language as needed
                    } else {
                        outputChannel.appendLine('Unexpected response format');
                    }
                });
                

                stream.on('end', () => {
                    outputChannel.appendLine('\n\nCode generation complete.');
                });

            } catch (error: any) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }

        } else {
            vscode.window.showErrorMessage('No active editor found.');
        }
    });

    context.subscriptions.push(disposable);
}

vscode.commands.registerCommand('extension.copyToClipboard', (code: string) => {
    vscode.env.clipboard.writeText(code);
    vscode.window.showInformationMessage('Code copied to clipboard!');
});


export function deactivate() {}
 