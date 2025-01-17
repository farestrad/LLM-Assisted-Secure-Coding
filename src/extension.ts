import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { SecurityAnalysisProvider } from './SecurityAnalysisProvider';  
import { AISuggestionHistoryProvider, AISuggestion } from './AISuggestionHistoryProvider';  
import { VulnerabilityDatabaseProvider } from './VulnerabilityDatabaseProvider';

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

        // Clear existing results in the Security Analysis panel
        securityAnalysisProvider.clear();

        // Run security analysis
        vscode.window.showInformationMessage('Running security analysis...');
        await securityAnalysisProvider.analyzeLatestGeneratedCode();

        // Fetch CVE details based on detected issues
        const detectedIssues = securityAnalysisProvider['securityIssues']; // Access detected issues

        if (detectedIssues.length > 0) {
            try {
                const cveDetails = [];
                for (const issue of detectedIssues) {
                    // Ensure issue.label is a string
                    const issueLabel = typeof issue.label === 'string' ? issue.label : 'Unknown Issue';
        
                    // Fetch CVE details using the validated string label
                    const fetchedCves = await vulnerabilityDatabaseProvider.fetchMultipleCveDetails(issueLabel);
        
                    // Map fetched CVEs into the desired format and add them to the list
                    cveDetails.push(...fetchedCves.map(cve => ({
                        id: cve.id,
                        description: cve.descriptions[0]?.value || 'No description available',
                    })));
                }
        
                // Update CVE details in the Security Analysis panel
                securityAnalysisProvider.updateCveDetails(cveDetails);
                vscode.window.showInformationMessage('CVE details fetched and updated successfully.');
            } catch (error) {
                vscode.window.showErrorMessage(
                    `Failed to fetch CVE details: ${error instanceof Error ? error.message : 'Unknown error'}`
                );
            }
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

            outputChannel.appendLine('Generating code with Code Llama...');

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
