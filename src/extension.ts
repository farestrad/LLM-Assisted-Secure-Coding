import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { SecurityAnalysisProvider } from './SecurityAnalysisProvider';  

export function activate(context: vscode.ExtensionContext) {
    // Create an instance of GeneratedCodeProvider to manage sidebar data
    const generatedCodeProvider = new GeneratedCodeProvider();
    
    // Register the provider with the view ID from package.json
    vscode.window.registerTreeDataProvider('codeLlamaGeneratedCodeView', generatedCodeProvider);

    // Security Analysis output
    const securityAnalysisProvider = new SecurityAnalysisProvider();  // Create the provider
    vscode.window.registerTreeDataProvider('securityAnalysisView', securityAnalysisProvider);  // Register the view

    vscode.commands.registerCommand('extension.runSecurityAnalysis', () => {
        // For now, we'll simulate security issues with mock data
        const mockSecurityIssues = [
            "Potential SQL Injection - Line 15",
            "Insecure password storage - Line 24",
            "Hard Coring - Line 34"
        ];

        securityAnalysisProvider.updateSecurityAnalysis(mockSecurityIssues);
        vscode.window.showInformationMessage('Security analysis completed.');
    });

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
                    try {
                        // Attempt to parse the chunk as JSON
                        const jsonChunk = JSON.parse(chunk.toString());
                
                        // Debugging: Log the structure of the chunk to better understand the response
                        console.log('Received chunk:', jsonChunk);
                     /*   outputChannel.appendLine(`Received chunk: ${JSON.stringify(jsonChunk, null, 2)}`);
                        ONLY UNCOMMENT THIS LINE IF YOU WANT A DETAILED LOG (WITH FIELDS) OF THE CODE LLAMA RESPONSE */
                        // Check if the expected field is present
                        if (jsonChunk.response && jsonChunk.response !== "") {
                            const outputText = jsonChunk.response;
                            partialResponse += outputText;
                
                            // Update the output channel
                            outputChannel.append(outputText);
                
                            // Update the sidebar with syntax-highlighted code (for example, 'java')
                            generatedCodeProvider.updateGeneratedCode(partialResponse, 'java');
                        }
                
                        // Handle the "done" field (final chunk)
                        if (jsonChunk.done) {
                            outputChannel.appendLine('\n\nCode generation complete.');
                        }
                        
                    } catch (error) {
                        const err = error as Error;  // Cast 'error' to 'Error' type
                        outputChannel.appendLine(`Error parsing response: ${err.message}`);
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
 