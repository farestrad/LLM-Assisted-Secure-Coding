import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { SecurityAnalysisProvider } from './SecurityAnalysisProvider';  
import { AISuggestionHistoryProvider, AISuggestion } from './AISuggestionHistoryProvider';  // Import AISuggestion

export function activate(context: vscode.ExtensionContext) {
    // Create an instance of GeneratedCodeProvider to manage sidebar data
    const generatedCodeProvider = new GeneratedCodeProvider();
    
    // Register the provider with the view ID from package.json
    vscode.window.registerTreeDataProvider('codeLlamaGeneratedCodeView', generatedCodeProvider);

    // Security Analysis output
    const securityAnalysisProvider = new SecurityAnalysisProvider();  // Create the provider
    vscode.window.registerTreeDataProvider('securityAnalysisView', securityAnalysisProvider);  // Register the view

    const aiSuggestionHistoryProvider = new AISuggestionHistoryProvider();
    vscode.window.registerTreeDataProvider('aiSuggestionHistoryView', aiSuggestionHistoryProvider);

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
                        prompt: `From the above code, provide a vulnerability analysis with vulnerability rating based on the CVSS model and provide the vulnerability type, reasoning for the vulnerability, vulnerability severity, and proposal for fixing. ${selectedText}`,
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
                            // outputChannel.appendLine('\n\nCode generation complete.');
                          
                            // Log AI suggestions
                            aiSuggestionHistoryProvider.addAISuggestion(partialResponse, selectedText);
                        }
                        
                    } catch (error) {
                        const err = error as Error;  // Cast 'error' to 'Error' type
                        outputChannel.appendLine(`Error parsing response: ${err.message}`);
                    }
                });
                

                stream.on('end', () => {
                    outputChannel.appendLine('\n\nVulnerability Assessment Complete.');
                });

            } catch (error: any) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }

        } else {
            vscode.window.showErrorMessage('No active editor found.');
        }
    });

    context.subscriptions.push(disposable);

    // Copy to clipboard command (same as before)
    vscode.commands.registerCommand('extension.copyToClipboard', (code: string) => {
        vscode.env.clipboard.writeText(code);
        vscode.window.showInformationMessage('Code copied to clipboard!');
    });

    // Commands for accepting, rejecting, and undoing AI suggestions

vscode.commands.registerCommand('extension.acceptAISuggestion', async (element: AISuggestion) => {
    const suggestions = await aiSuggestionHistoryProvider.getChildren();  // Get the list of suggestions
    const id = suggestions ? suggestions.indexOf(element) : -1;  // Find the index of the element
    if (id >= 0) {
        aiSuggestionHistoryProvider.updateAISuggestionStatus(id, 'accepted');
        vscode.window.showInformationMessage('AI suggestion accepted.');
    } else {
        vscode.window.showErrorMessage('AI suggestion not found.');
    }
});


// Register the Reject AI Suggestion command
vscode.commands.registerCommand('extension.rejectAISuggestion', async (element: AISuggestion) => {
    const suggestions = await aiSuggestionHistoryProvider.getChildren();  // Get the list of suggestions
    const id = suggestions ? suggestions.indexOf(element) : -1;  // Find the index of the element
    if (id >= 0) {
        aiSuggestionHistoryProvider.updateAISuggestionStatus(id, 'rejected');
        vscode.window.showInformationMessage('AI suggestion rejected.');
    } else {
        vscode.window.showErrorMessage('AI suggestion not found.');
    }
});

vscode.commands.registerCommand('extension.toggleSuggestionStatus', (element: AISuggestion) => {
    // Toggle between 'accepted' and 'rejected'
    if (element.status === 'pending' || element.status === 'rejected') {
        element.status = 'accepted';
        vscode.window.showInformationMessage(`AI suggestion accepted.`);
    } else {
        element.status = 'rejected';
        vscode.window.showInformationMessage(`AI suggestion rejected.`);
    }

    aiSuggestionHistoryProvider.refresh();  // Refresh the TreeView to update the status
});



}

export function deactivate() {}


 