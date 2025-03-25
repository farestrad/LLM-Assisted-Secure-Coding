import * as vscode from 'vscode';

export class GettingStartedPanelProvider {
    public static panel: vscode.WebviewPanel | undefined;

    public static createOrShow(context: vscode.ExtensionContext) {
        if (GettingStartedPanelProvider.panel) {
            GettingStartedPanelProvider.panel.reveal(vscode.ViewColumn.One);
            return;
        }

        GettingStartedPanelProvider.panel = vscode.window.createWebviewPanel(
            'safeScriptGettingStarted',
            'SafeScript - Getting Started',
            vscode.ViewColumn.One,
            { 
                enableScripts: true, 
                retainContextWhenHidden: true
            }
        );

        GettingStartedPanelProvider.panel.webview.html = GettingStartedPanelProvider.getHtmlContent();
        
        GettingStartedPanelProvider.panel.onDidDispose(() => {
            GettingStartedPanelProvider.panel = undefined;
        }, null, context.subscriptions);
        
        GettingStartedPanelProvider.panel.webview.onDidReceiveMessage(message => {
            switch (message.command) {
                case 'runCommand':
                    vscode.commands.executeCommand(message.value);
                    break;
            }
        }, undefined, context.subscriptions);
        
        context.subscriptions.push(GettingStartedPanelProvider.panel);
    }

    private static getHtmlContent(): string {
        return `<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px;
            line-height: 1.6;
            max-width: 1000px;
            margin: 0 auto;
        }
        h1, h2, h3 {
            color: var(--vscode-editor-foreground);
            font-weight: 600;
        }
        h1 {
            font-size: 2.2em;
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 12px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        h1::before {
            content: "";
            display: inline-block;
            width: 32px;
            height: 32px;
            background-color: var(--vscode-activityBarBadge-background);
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-size: contain;
        }
        h2 {
            font-size: 1.6em;
            margin-top: 32px;
            margin-bottom: 16px;
            color: var(--vscode-activityBarBadge-background);
        }
        h3 {
            font-size: 1.3em;
            margin-top: 24px;
            margin-bottom: 12px;
        }
        .hero {
            background: linear-gradient(135deg, 
                rgba(var(--vscode-activityBarBadge-background), 0.1), 
                rgba(var(--vscode-editor-background), 0.3));
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 32px;
            position: relative;
            overflow: hidden;
            border: 1px solid var(--vscode-panel-border);
        }
        .hero::after {
            content: "";
            position: absolute;
            top: 0;
            right: 0;
            bottom: 0;
            width: 30%;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200' viewBox='0 0 100 100' preserveAspectRatio='none'%3E%3Cpath d='M50,0 L100,0 L100,100 L50,100 C70,70 70,30 50,0' fill='rgba(100,200,255,0.05)'/%3E%3C/svg%3E");
            background-size: cover;
            z-index: 0;
            opacity: 0.7;
        }
        .hero-content {
            position: relative;
            z-index: 1;
        }
        .hero p {
            font-size: 1.1em;
            max-width: 85%;
            margin: 0;
        }
        .card {
            background-color: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
            margin-top: 24px;
        }
        .feature-item {
            background-color: var(--vscode-panel-background);
            border-radius: 6px;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        .feature-item::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 6px;
            height: 100%;
            background-color: var(--vscode-activityBarBadge-background);
            opacity: 0.7;
        }
        .feature-title {
            font-weight: bold;
            margin-bottom: 12px;
            color: var(--vscode-activityBarBadge-background);
            font-size: 1.1em;
        }
        kbd {
            background-color: var(--vscode-button-secondaryBackground);
            border-radius: 3px;
            border: 1px solid var(--vscode-panel-border);
            box-shadow: 0 1px 0 rgba(0,0,0,0.2);
            color: var(--vscode-button-secondaryForeground);
            display: inline-block;
            font-size: 0.85em;
            font-family: sans-serif;
            line-height: 1;
            padding: 2px 5px;
            margin: 0 2px;
        }
        .shortcut-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            margin-bottom: 24px;
        }
        .shortcut-table th, .shortcut-table td {
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .shortcut-table th {
            font-weight: 600;
            color: var(--vscode-activityBarBadge-background);
        }
        .shortcut-table tr:last-child td {
            border-bottom: none;
        }
        .tip {
            background-color: var(--vscode-textBlockQuote-background);
            border-left: 4px solid var(--vscode-activityBarBadge-background);
            padding: 12px 16px;
            margin: 24px 0;
            border-radius: 0 4px 4px 0;
        }
        .tip::before {
            content: "💡 ";
        }
        .panel-preview {
            background-color: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 16px;
            margin: 20px 0;
            position: relative;
        }
        .panel-header {
            background-color: var(--vscode-panel-background);
            padding: 8px 12px;
            border-radius: 4px 4px 0 0;
            font-weight: 500;
            border-bottom: 1px solid var(--vscode-panel-border);
            margin: -16px -16px 16px -16px;
            display: flex;
            align-items: center;
        }
        .panel-header::before {
            content: "";
            display: inline-block;
            width: 16px;
            height: 16px;
            margin-right: 8px;
            background-color: var(--vscode-activityBarBadge-background);
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'%3E%3C/path%3E%3Cpath d='M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71'%3E%3C/path%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-size: contain;
        }
        .panel-body {
            font-size: 0.95em;
            line-height: 1.5;
        }
        .text-highlight {
            color: var(--vscode-activityBarBadge-background);
            font-weight: 500;
        }
        .workflow-step {
            display: flex;
            gap: 16px;
            margin: 20px 0;
            align-items: center;
        }
        .step-number {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background-color: var(--vscode-activityBarBadge-background);
            color: var(--vscode-editor-background);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            flex-shrink: 0;
        }
        .step-content {
            flex: 1;
        }
        .step-content strong {
            color: var(--vscode-activityBarBadge-background);
        }
        .toggle-preview {
            background-color: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 20px;
            display: flex;
            overflow: hidden;
            width: 300px;
            margin: 0 auto;
        }
        .toggle-option {
            flex: 1;
            padding: 8px 12px;
            text-align: center;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        .toggle-active {
            background-color: var(--vscode-activityBarBadge-background);
            color: var(--vscode-editor-background);
            font-weight: 500;
        }
        .analysis-sample {
            background-color: rgba(var(--vscode-activityBarBadge-background), 0.1);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            padding: 12px;
            margin-top: 12px;
            font-family: monospace;
            font-size: 0.9em;
            color: var(--vscode-editor-foreground);
        }
        .features-container {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
        }
        .features-column {
            flex: 1;
            min-width: 300px;
        }
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--vscode-panel-border);
            text-align: center;
            color: var(--vscode-textLink-foreground);
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>SafeScript</h1>
    
    <div class="hero">
        <div class="hero-content">
            <p>AI-powered code security analysis and generation for VS Code. Identify vulnerabilities in your code and generate secure alternatives with Code Llama.</p>
        </div>
    </div>

    <h2>Dual-Mode Interface</h2>
    
    <div class="panel-preview">
        <div class="panel-header">Mode Selector</div>
        <div class="panel-body">
            <p>SafeScript features a dual-mode interface to better serve your development workflow:</p>
            
            <div class="toggle-preview">
                <div class="toggle-option toggle-active">Analyze & Improve</div>
                <div class="toggle-option">Generate Code</div>
            </div>
            
            <p><span class="text-highlight">Analyze & Improve:</span> For analyzing existing code and finding security vulnerabilities.</p>
            
            <p><span class="text-highlight">Generate Code:</span> Quickly generate secure C code based on your requirements that you can later analyze.</p>
        </div>
    </div>

    <div class="tip">
        Switch between modes using the toggle at the top of the panel. Each mode has context-specific buttons and placeholder text to guide you.
    </div>

    <div class="features-container">
        <div class="features-column">
            <h2>Core Features</h2>
            <div class="grid">
                <div class="feature-item">
                    <div class="feature-title">Security Analysis</div>
                    <p>Scan your code for potential security vulnerabilities like buffer overflows, memory leaks, and more.</p>
                    <p>Use <kbd>Ctrl+Alt+R</kbd> for entire file, <kbd>Ctrl+Alt+H</kbd> for selected code</p>
                </div>
                
                <div class="feature-item">
                    <div class="feature-title">Code Generation</div>
                    <p>Generate secure C code from natural language descriptions with the dedicated code generation interface.</p>
                </div>
            </div>
        </div>
        
        <div class="features-column">
            <h2>Advanced Tools</h2>
            <div class="grid">
                <div class="feature-item">
                    <div class="feature-title">CVE Database</div>
                    <p>Look up information about known vulnerabilities from the CVE database.</p>
                    <p>Use <kbd>Ctrl+Alt+C</kbd> to fetch CVE details</p>
                </div>
                
                <div class="feature-item">
                    <div class="feature-title">AI Suggestion History</div>
                    <p>Track and manage your history of AI-generated code improvements.</p>
                </div>
            </div>
        </div>
    </div>

    <h2>Complete Workflow</h2>
    
    <div class="card">
        <h3>Generate & Analyze Workflow</h3>
        
        <div class="workflow-step">
            <div class="step-number">1</div>
            <div class="step-content">
                <strong>Select your mode</strong> using the toggle at the top of the interface (Generate Code or Analyze & Improve).
            </div>
        </div>
        
        <div class="workflow-step">
            <div class="step-number">2</div>
            <div class="step-content">
                <strong>Generate or import code</strong> - Either describe the code you need to generate or paste existing code for analysis.
            </div>
        </div>
        
        <div class="workflow-step">
            <div class="step-number">3</div>
            <div class="step-content">
                <strong>Review analysis results</strong> - See detected vulnerabilities and their details or examine generated code.
            </div>
        </div>
        
        <div class="workflow-step">
            <div class="step-number">4</div>
            <div class="step-content">
                <strong>Implement security improvements</strong> - Apply generated secure code or suggested fixes to your project.
            </div>
        </div>
    </div>

    <h2>Interface Overview</h2>
    
    <div class="panel-preview">
        <div class="panel-header">SafeScript Panel Features</div>
        <div class="panel-body">
            <p><span class="text-highlight">Mode-Specific UI:</span> The interface adapts based on your selected mode:</p>
            
            <p><span class="text-highlight">Generate Code Mode:</span> Shows "Copy Code" and "Analyze This Code" buttons for generated content.</p>
            
            <p><span class="text-highlight">Analyze & Improve Mode:</span> Provides full suggestion management with "Add to Suggestion History" option.</p>
            
            <p><span class="text-highlight">Security Analysis:</span> Displays vulnerabilities with detailed descriptions.</p>
            
            <div class="analysis-sample">
            // Security Issues:
            // - Buffer overflow vulnerability in strcpy()
            // - No bounds checking on user input
            // - Memory leak in allocated buffer
            </div>
        </div>
    </div>

    <h2>Key Shortcuts</h2>
    
    <table class="shortcut-table">
        <tr>
            <th>Action</th>
            <th>Shortcut</th>
        </tr>
        <tr>
            <td>Show Getting Started Panel</td>
            <td><kbd>Ctrl+Alt+M</kbd></td>
        </tr>
        <tr>
            <td>Show Analysis and Improvement Panel</td>
            <td><kbd>Ctrl+Alt+P</kbd></td>
        </tr>
        <tr>
            <td>Run Security Analysis</td>
            <td><kbd>Ctrl+Alt+R</kbd></td>
        </tr>
        <tr>
            <td>Analyze Highlighted Code</td>
            <td><kbd>Ctrl+Alt+H</kbd></td>
        </tr>
        <tr>
            <td>Fetch CVE Details</td>
            <td><kbd>Ctrl+Alt+C</kbd></td>
        </tr>
    </table>

    <h2>Best Practices</h2>
    
    <div class="tip">
        Run security analysis frequently during development, not just at the end. Address high-severity vulnerabilities first and study the AI-suggested improvements to learn secure coding patterns.
    </div>

    <div class="tip">
        The "Generate Code" mode is perfect for quickly creating secure code snippets that follow best practices, which you can then further analyze and refine.
    </div>

    <h2>Views & Panels</h2>
    <p>SafeScript provides multiple views to help you work with its features:</p>
    
    <div class="panel-preview">
        <div class="panel-header">Available SafeScript Views</div>
        <div class="panel-body">
            <p><span class="text-highlight">Security Analysis:</span> Results of security scans with detailed vulnerability descriptions</p>
            
            <p><span class="text-highlight">AI Suggestions History:</span> Track your history of AI suggestions and implementation status</p>
        </div>
    </div>
    
    <h2>Getting the Most from SafeScript</h2>
    
    <div class="card">
        <h3>Best Practices</h3>
        <ul>
            <li><strong>Regular Analysis:</strong> Run security analysis frequently during development, not just at the end</li>
            <li><strong>Focus on Critical Issues:</strong> Address high-severity vulnerabilities first</li>
            <li><strong>Understand the Fixes:</strong> Study the AI-suggested improvements to learn secure coding patterns</li>
            <li><strong>Keep a Suggestion Library:</strong> Save useful code improvements in your AI suggestion history</li>
            <li><strong>Combine with Code Reviews:</strong> Use SafeScript alongside traditional code review processes</li>
        </ul>
    </div>

    <footer>
        SafeScript: Making secure code development simpler and more accessible
    </footer>

    <script>
        const vscode = acquireVsCodeApi();
        
        function runCommand(command) {
            vscode.postMessage({
                command: "runCommand",
                value: command
            });
        }
    </script>
</body>
</html>`;
    }

    public static dispose() {
        if (GettingStartedPanelProvider.panel) {
            GettingStartedPanelProvider.panel.dispose();
        }
    }
}