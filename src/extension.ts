import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { SecurityAnalysisProvider } from './SecurityAnalysisProvider';  
import { AISuggestionHistoryProvider, AISuggestion } from './AISuggestionHistoryProvider';  
import { VulnerabilityDatabaseProvider } from './VulnerabilityDatabaseProvider';
import { trackEvent } from './amplitudeTracker';


// Activate function
export function activate(context: vscode.ExtensionContext) {
    // Initialize providers
    const generatedCodeProvider = new GeneratedCodeProvider();
    const securityAnalysisProvider = new SecurityAnalysisProvider(generatedCodeProvider);
    const aiSuggestionHistoryProvider = new AISuggestionHistoryProvider();
    const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();



    // Register views
    vscode.window.registerTreeDataProvider('codeLlamaGeneratedCodeView', generatedCodeProvider);
    vscode.window.registerTreeDataProvider('securityAnalysisView', securityAnalysisProvider);
    vscode.window.registerTreeDataProvider('aiSuggestionHistoryView', aiSuggestionHistoryProvider);

    // Command: Run Security Analysis
    vscode.commands.registerCommand('extension.runSecurityAnalysis', async () => {
        const editor = vscode.window.activeTextEditor;
    
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found. Please open a file to analyze.');
            return;
        }
    
        const code = editor.document.getText();
        if (!code) {
            vscode.window.showWarningMessage('No code found in the editor. Please write some code to analyze.');
            return;
        }
    
        // Use the instance of SecurityAnalysisProvider instead of the class
        securityAnalysisProvider.clear();
    
        // Run security analysis
        vscode.window.showInformationMessage('Running security analysis...');
        await securityAnalysisProvider.analyzeLatestGeneratedCode();
    
        // Get security issues from the provider instance
        const detectedIssues = await securityAnalysisProvider.getChildren(
            new vscode.TreeItem('Security Issues', vscode.TreeItemCollapsibleState.Collapsed)
        );
    
        if (detectedIssues.length > 0 && detectedIssues[0].label !== "No security issues found!") {
            vscode.window.showInformationMessage('Security analysis completed. Check the Security Analysis panel for results.');
        } else {
            vscode.window.showInformationMessage('No security issues detected.');
        }
    });
    

    // Command: Generate Code with Code Llama
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
            
            
            trackEvent('code_generation_initiated', {
                user_id: vscode.env.machineId,
                selected_text_length: selectedText.length,
                timestamp: new Date().toISOString()
            });

            outputChannel.appendLine('Generating code with AI...');//adding this here since deepseek is the same as codellama or llama3 so not much different doesnt hurt to have the look of we are using deepseek tho!

            try {
                const response = await fetch('http://172.105.25.95:11434/api/generate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        model: 'llama3',
                        prompt: `Only provide the C code with no additional explanation, comments, NO extra text, and do not write the letter c  on top . Write the C code to accomplish the following task: ${selectedText}`,
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
            
            trackEvent('ai_suggestion_accepted', {
                user_id: vscode.env.machineId,
                suggestion_length: element.suggestion.length,
                timestamp: new Date().toISOString()
            });
        
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
        
            trackEvent('ai_suggestion_rejected', {
                user_id: vscode.env.machineId,
                suggestion_length: element.suggestion.length,
                timestamp: new Date().toISOString()
            });
        
        
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


vscode.commands.registerCommand('extension.fetchCveDetails', async () => {
    const provider = new VulnerabilityDatabaseProvider();
    const cveId = await vscode.window.showInputBox({
        prompt: 'Enter the CVE ID to fetch details (e.g., CVE-2023-1234)',
    });

    if (!cveId) {
        vscode.window.showWarningMessage('No CVE ID entered. Fetch operation canceled.');
        return;
    }

    try {
        const cveDetails = await provider.fetchCveDetails(cveId);

        // Extract relevant details
        const title = cveDetails.cveMetadata?.cveId || 'Unknown CVE ID';
        const state = cveDetails.cveMetadata?.state || 'Unknown state';
        const description =
            cveDetails.containers?.cna?.descriptions?.[0]?.value ||
            'No description available.';
        const affectedProducts =
            cveDetails.containers?.cna?.affected
                ?.map((affected: { vendor: string; product: string; versions?: { version: string }[] }) => {
                    return `- Vendor: ${affected.vendor}, Product: ${affected.product}, Versions: ${
                        affected.versions?.map((v) => v.version).join(', ') || 'Unknown'
                    }`;
                })
                .join('\n') || 'No affected products listed.';

        // Display the formatted details in a message
        const formattedDetails = `**CVE Details**\n
**ID**: ${title}
**State**: ${state}
**Description**: ${description}
**Affected Products**:\n${affectedProducts}`;

vscode.window.showInformationMessage(formattedDetails, { modal: true });
} catch (error: any) {
    // Handle known errors with specific status codes
    if (error.response?.status === 404) {
        vscode.window.showWarningMessage(
            `CVE ID "${cveId}" is not listed in the database.`
        );
    } else if (error.response?.status === 400) {
        vscode.window.showWarningMessage(
            `CVE ID "${cveId}" is invalid. Please check the format.`
        );
    } else {
        // Handle other errors
        vscode.window.showErrorMessage(
            `Failed to fetch CVE details for "${cveId}": ${
                error instanceof Error ? error.message : 'Unknown error'
            }`
        );
    }
}
});


export function deactivate() {}
