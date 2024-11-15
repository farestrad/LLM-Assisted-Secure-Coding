import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { SecurityAnalysisProvider } from './SecurityAnalysisProvider';  
import { AISuggestionHistoryProvider, AISuggestion } from './AISuggestionHistoryProvider';  // Import AISuggestion

export function activate(context: vscode.ExtensionContext) {
    // Create an instance of GeneratedCodeProvider to manage sidebar data
    const generatedCodeProvider = new GeneratedCodeProvider();
    vscode.window.registerTreeDataProvider('codeLlamaGeneratedCodeView', generatedCodeProvider);

    // Security Analysis output, with access to GeneratedCodeProvider
    const securityAnalysisProvider = new SecurityAnalysisProvider(generatedCodeProvider);
    vscode.window.registerTreeDataProvider('securityAnalysisView', securityAnalysisProvider);

    // Initialize the AI Suggestion History Provider
    const aiSuggestionHistoryProvider = new AISuggestionHistoryProvider();
    vscode.window.registerTreeDataProvider('aiSuggestionHistoryView', aiSuggestionHistoryProvider);

    // Command to trigger a security analysis manually on the latest generated code
    vscode.commands.registerCommand('extension.runSecurityAnalysis', () => {
        securityAnalysisProvider.analyzeLatestGeneratedCode();
        vscode.window.showInformationMessage('Security analysis completed.');
    });

    // Command to trigger Code Llama generation and display the output
    const disposable = vscode.commands.registerCommand('codeLlama.runCodeLlama', async () => {
        const outputChannel = vscode.window.createOutputChannel("Code Llama Output");
        outputChannel.show(true);

        const editor = vscode.window.activeTextEditor;

        if (editor) {
            const selection = editor.selection;
            const selectedText = editor.document.getText(selection);

            if (!selectedText) {
                vscode.window.showErrorMessage('Please select the line you want to check.');
                return;
            }

            outputChannel.appendLine('Generating code with Code Llama...');

            try {
                const response = await fetch('http://178.128.231.154:11434/api/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        model: 'llama3',
                        prompt: `Only provide the C code with no additional explanation, comments, or extra text at all, and do not write the letter c on top or anywhere else. Write the C code to accomplish the following task: ${selectedText}`,
                        stream: true,
                    }),
                });

                if (!response.ok) {
                    throw new Error('Error generating code. Please try again.');
                }

                const stream = response.body as unknown as NodeJS.ReadableStream;
                let partialResponse = '';

                stream.on('data', (chunk) => {
                    try {
                        const jsonChunk = JSON.parse(chunk.toString());
                        console.log('Received chunk:', jsonChunk);

                        if (jsonChunk.response && jsonChunk.response !== "") {
                            const outputText = jsonChunk.response;
                            partialResponse += outputText;
                            outputChannel.append(outputText);
                            generatedCodeProvider.updateGeneratedCode(partialResponse, 'c'); // Assume C language

                            // Trigger security analysis on the generated code
                            securityAnalysisProvider.analyzeLatestGeneratedCode();
                        }

                        if (jsonChunk.done) {
                            aiSuggestionHistoryProvider.addAISuggestion(partialResponse, selectedText);
                        }
                    } catch (error) {
                        const err = error as Error;
                        outputChannel.appendLine(`Error parsing response: ${err.message}`);
                    }
                });

                stream.on('end', () => {
                    outputChannel.appendLine('\n\nCode Generation Completed.');
                });

            } catch (error: any) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }

        } else {
            vscode.window.showErrorMessage('No active editor found.');
        }
    });

    context.subscriptions.push(disposable);

    // Copy to clipboard command
    vscode.commands.registerCommand('extension.copyToClipboard', (code: string) => {
        vscode.env.clipboard.writeText(code);
        vscode.window.showInformationMessage('Code copied to clipboard!');
    });

    // Commands for managing AI suggestions
    vscode.commands.registerCommand('extension.acceptAISuggestion', async (element: AISuggestion) => {
        const suggestions = await aiSuggestionHistoryProvider.getChildren();
        const id = suggestions ? suggestions.indexOf(element) : -1;
        if (id >= 0) {
            aiSuggestionHistoryProvider.updateAISuggestionStatus(id, 'accepted');
            vscode.window.showInformationMessage('AI suggestion accepted.');
        } else {
            vscode.window.showErrorMessage('AI suggestion not found.');
        }
    });

    vscode.commands.registerCommand('extension.rejectAISuggestion', async (element: AISuggestion) => {
        const suggestions = await aiSuggestionHistoryProvider.getChildren();
        const id = suggestions ? suggestions.indexOf(element) : -1;
        if (id >= 0) {
            aiSuggestionHistoryProvider.updateAISuggestionStatus(id, 'rejected');
            vscode.window.showInformationMessage('AI suggestion rejected.');
        } else {
            vscode.window.showErrorMessage('AI suggestion not found.');
        }
    });

    vscode.commands.registerCommand('extension.toggleSuggestionStatus', (element: AISuggestion) => {
        if (element.status === 'pending' || element.status === 'rejected') {
            element.status = 'accepted';
            vscode.window.showInformationMessage(`AI suggestion accepted.`);
        } else {
            element.status = 'rejected';
            vscode.window.showInformationMessage(`AI suggestion rejected.`);
        }

        aiSuggestionHistoryProvider.refresh();
    });
}

export function deactivate() {}
