import * as vscode from 'vscode';
import fetch from 'node-fetch';
import { GeneratedCodeProvider } from './generatedCodeProvider';
import { SecurityAnalysisProvider } from './SecurityAnalysisProvider';
import { AISuggestionHistoryProvider, AISuggestion } from './AISuggestionHistoryProvider';
import { VulnerabilityDatabaseProvider } from './VulnerabilityDatabaseProvider';
import { trackEvent } from './amplitudeTracker';
import { SafeScriptViewProvider } from './safeScriptViewProvider';
import { SafeScriptPanelRight } from './safeScriptPanelRight';
import { GettingStartedPanelProvider } from './GettingStartedPanelProvider';

export function activate(context: vscode.ExtensionContext) {
    // Initialize providers
    const generatedCodeProvider = new GeneratedCodeProvider();
    const securityAnalysisProvider = new SecurityAnalysisProvider(generatedCodeProvider);
    const aiSuggestionHistoryProvider = new AISuggestionHistoryProvider();
    const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();

    // Always show getting started panel when extension is activated
    GettingStartedPanelProvider.createOrShow(context);

    // Command to show the getting started panel (for manual activation)
    const showGettingStartedCommand = vscode.commands.registerCommand('extension.showGettingStartedPanel', () => {
        GettingStartedPanelProvider.createOrShow(context);
    });
    context.subscriptions.push(showGettingStartedCommand);

    // Register the left sidebar SafeScript view provider
    const leftProvider = new SafeScriptViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(SafeScriptViewProvider.viewType, leftProvider)
    );

    // Command: Show the right SafeScript panel
    SafeScriptPanelRight.createOrShow(context, aiSuggestionHistoryProvider);
    const rightPanelCommand = vscode.commands.registerCommand('extension.safescript.showRightPanel', () => {
        SafeScriptPanelRight.createOrShow(context, aiSuggestionHistoryProvider);
    });
    context.subscriptions.push(rightPanelCommand);

    // Register tree data providers for the sub-modules
    vscode.window.registerTreeDataProvider('securityAnalysisView', securityAnalysisProvider);
    vscode.window.registerTreeDataProvider('aiSuggestionHistoryView', aiSuggestionHistoryProvider);

    // Register the copy suggestion command for AI suggestion history
    const copySuggestionCommand = vscode.commands.registerCommand('extension.copySuggestion', (suggestion: AISuggestion) => {
        if (suggestion) {
            vscode.env.clipboard.writeText(suggestion.suggestion);
            vscode.window.showInformationMessage('Suggestion copied to clipboard');
        }
    });
    context.subscriptions.push(copySuggestionCommand);

    // ----------------------------
    // Command: Run Security Analysis on entire active file
    // ----------------------------
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

        // Clear previous analysis results
        securityAnalysisProvider.clear();

        // Ensure the right panel is created and visible
        SafeScriptPanelRight.createOrShow(context);

        // Initialize with "analyzing" message
        SafeScriptPanelRight.postMessage({
            command: 'updateIssues',
            issues: "Analyzing code for security issues..."
        });

        vscode.window.showInformationMessage('Running security analysis...');

        // Run the analysis
        await securityAnalysisProvider.analyzeCode(code);
    });

    // ----------------------------
    // Command: Run Security Analysis on Highlighted Code
    // ----------------------------
    vscode.commands.registerCommand('extension.analyzeHighlightedCode', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor found. Please open a file to analyze.');
            return;
        }

        const selection = editor.selection;
        const highlightedCode = editor.document.getText(selection);

        if (!highlightedCode || highlightedCode.trim() === '') {
            vscode.window.showWarningMessage('No code highlighted. Please select code to analyze.');
            return;
        }

        // Track the event
        trackEvent('highlighted_code_analysis', {
            user_id: vscode.env.machineId,
            code_length: highlightedCode.length,
            language: editor.document.languageId,
            timestamp: new Date().toISOString()
        });

        // Clear previous analysis results
        securityAnalysisProvider.clear();

        // Ensure the right panel is created and visible
        SafeScriptPanelRight.createOrShow(context);

        // Initialize with "analyzing" message
        SafeScriptPanelRight.postMessage({
            command: 'updateIssues',
            issues: "Analyzing highlighted code for security issues..."
        });

        vscode.window.showInformationMessage('Running security analysis on highlighted code...');

        // Run the analysis on the highlighted code
        await securityAnalysisProvider.analyzeCode(highlightedCode);
    });

    // ----------------------------
    // Command: Analyze Code from Right Panel
    // ----------------------------
    vscode.commands.registerCommand('extension.analyzeCodeFromRightPanel', async (code: string) => {
        if (!code || code.trim() === '') {
            vscode.window.showWarningMessage('No code provided for analysis.');
            return "No code provided for analysis.";
        }

        // Track the event
        trackEvent('right_panel_code_analysis', {
            user_id: vscode.env.machineId,
            code_length: code.length,
            timestamp: new Date().toISOString()
        });

        // Clear previous analysis results
        securityAnalysisProvider.clear();

        // Initialize with "analyzing" message
        SafeScriptPanelRight.postMessage({
            command: 'analysisStatus',
            status: "Analyzing code for security issues..."
        });

        // Run the analysis on the provided code
        await securityAnalysisProvider.analyzeCode(code);

        // Return a success message since getRawSecurityIssues is removed
        return "Security analysis complete. Check results in the panel.";
    });

    // ----------------------------
    // Command: Generate Code with Code Llama
    // ----------------------------
    const disposable = vscode.commands.registerCommand('codeLlama.runCodeLlama', async () => {
        const outputChannel = vscode.window.createOutputChannel("Code Llama Output");
        outputChannel.show(true);

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor found.');
            return;
        }

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

        outputChannel.appendLine('Generating code with AI...');

        try {
            const response = await fetch('http://34.130.23.243:11434/api/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    model: 'llama3',
                    prompt: `Only provide the C code with no additional explanation, comments, backticks, NO extra text, and do not write the letter c on top. Write only pure C code to accomplish the following task: ${selectedText}`,
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
                    if (jsonChunk.response && jsonChunk.response !== "") {
                        const outputText = jsonChunk.response;
                        partialResponse += outputText;
                        outputChannel.append(outputText);
                        generatedCodeProvider.updateGeneratedCode(partialResponse, 'c');

                        // Trigger security analysis on the generated code
                        securityAnalysisProvider.analyzeLatestGeneratedCode();
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
    });

    context.subscriptions.push(disposable);

    // Copy to clipboard command
    vscode.commands.registerCommand('extension.copyToClipboard', (code: string) => {
        vscode.env.clipboard.writeText(code);
        vscode.window.showInformationMessage('Code copied to clipboard!');
    });

    // ----------------------------
    // Command: Accept AI Suggestion
    // ----------------------------
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

            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage("No active editor found.");
                return;
            }

            const selection = editor.selection;
            editor.edit(editBuilder => {
                editBuilder.replace(selection, element.suggestion);
            }).then(success => {
                if (!success) {
                    vscode.window.showInformationMessage('Suggestion not inserted');
                }
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

    // ----------------------------
    // Command: Accept Generated Code
    // ----------------------------
    vscode.commands.registerCommand('extension.acceptGeneratedCode', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage("No active editor found.");
            return;
        }

        const selection = editor.selection;
        editor.edit(editBuilder => {
            editBuilder.replace(selection, generatedCodeProvider.getLatestGeneratedCode());
        }).then(success => {
            if (!success) {
                vscode.window.showInformationMessage('Generated code not accepted');
            }
        });
    });
}

// Deactivate function
export function deactivate() {}
