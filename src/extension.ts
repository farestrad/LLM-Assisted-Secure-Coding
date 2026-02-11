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
    // Command: Show Detail Panel (for security issues, CWEs, CVEs)
    // ----------------------------
    vscode.commands.registerCommand('extension.showDetailPanel', (title: string, content: string, type: 'issue' | 'cwe' | 'cve') => {
        const panel = vscode.window.createWebviewPanel(
            'safescriptDetail',
            title,
            vscode.ViewColumn.Beside,
            { enableScripts: true }
        );

        // Different styling based on type
        const iconMap = {
            'issue': '⚠️',
            'cwe': '🛡️',
            'cve': '🔓'
        };
        
        const colorMap = {
            'issue': '#f14c4c',
            'cwe': '#3794ff',
            'cve': '#ce9178'
        };

        panel.webview.html = `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                padding: 20px;
                background: #1e1e1e;
                color: #cccccc;
                line-height: 1.6;
            }
            .header {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid #3d3d3d;
            }
            .icon {
                font-size: 32px;
            }
            .title {
                color: ${colorMap[type]};
                font-size: 18px;
                font-weight: 600;
                margin: 0;
            }
            .content {
                background: #252526;
                padding: 16px;
                border-radius: 6px;
                border-left: 4px solid ${colorMap[type]};
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .actions {
                margin-top: 20px;
                display: flex;
                gap: 10px;
            }
            button {
                background: #0e639c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 13px;
            }
            button:hover {
                background: #1177bb;
            }
            button.secondary {
                background: transparent;
                border: 1px solid #3d3d3d;
                color: #cccccc;
            }
            button.secondary:hover {
                background: rgba(255,255,255,0.1);
            }
        </style>
    </head>
    <body>
        <div class="header">
            <span class="icon">${iconMap[type]}</span>
            <h1 class="title">${title}</h1>
        </div>
        <div class="content">${content}</div>
        <div class="actions">
            <button onclick="copyContent()">📋 Copy to Clipboard</button>
            <button class="secondary" onclick="closePanel()">Close</button>
        </div>
        <script>
            const vscode = acquireVsCodeApi();
            function copyContent() {
                navigator.clipboard.writeText(\`${content.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`);
                const btn = document.querySelector('button');
                btn.textContent = '✓ Copied!';
                setTimeout(() => btn.textContent = '📋 Copy to Clipboard', 2000);
            }
            function closePanel() {
                vscode.postMessage({ command: 'close' });
            }
        </script>
    </body>
    </html>`;
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
            const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`
                },
                body: JSON.stringify({
                    model: 'deepseek-coder',
                    messages: [
                        {
                            role: 'system',
                            content: 'Generate ONLY C code based on the following description. Intentionally include 1-2 subtle security vulnerabilities (such as buffer overflow, use of unsafe functions like strcpy/sprintf/gets, format string issues, or missing input validation) so the user can practice identifying and fixing them. Do NOT mention or comment about the vulnerabilities in the code. Only provide the C code with no additional explanation, comments, NO extra text, and do not write the letter c on top, do not generate backticks on top or below the c code. Write only pure C code.'
                            //content: 'Generate ONLY C code based on the following description. Only provide the C code with no additional explanation, comments, NO extra text, and do not write the letter c on top, do not generate backticks on top or below the c code. Write only pure C code.'
                        },
                        {
                            role: 'user',
                            content: selectedText
                        }
                    ],
                    stream: false
                }),
            });

            if (!response.ok) {
                throw new Error('Error generating code. Please try again.');
            }

            const data = await response.json() as any;
            const generatedCode = data.choices?.[0]?.message?.content || '';
            
            outputChannel.appendLine(generatedCode);
            generatedCodeProvider.updateGeneratedCode(generatedCode, 'c');
            
            // Trigger security analysis on the generated code
            securityAnalysisProvider.analyzeLatestGeneratedCode();
            
            outputChannel.appendLine('\n\nCode Generation Completed.');

        } catch (error: any) {
            vscode.window.showErrorMessage(`Error: ${error.message}`);
        }
    });

    context.subscriptions.push(disposable);

    // Copy to clipboard command
    vscode.commands.registerCommand('extension.copyToClipboard', (code: string) => {
        vscode.env.clipboard.writeText(code);
        vscode.window.showInformationMessage('Copied to clipboard!');
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
    
}

// Deactivate function
export function deactivate() {}
