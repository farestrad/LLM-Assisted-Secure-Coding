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
    <h1>Welcome to SafeScript</h1>
    
    <div class="hero">
        <div class="hero-content">
            <p>SafeScript enhances VS Code with Code Llama for AI-powered code analysis and security vulnerability detection. Write safer, more secure code by automatically identifying potential security issues in your code and generating more secure alternatives.</p>
        </div>
    </div>

    <h2>Understanding the SafeScript Experience</h2>
    
    <div class="card">
        <h3>Security Analysis & Improvement Workflow</h3>
        
        <div class="workflow-step">
            <div class="step-number">1</div>
            <div class="step-content">
                <strong>Analyze your code:</strong> SafeScript scans your code for potential security vulnerabilities like buffer overflows, memory leaks, and injection vulnerabilities.
            </div>
        </div>
        
        <div class="workflow-step">
            <div class="step-number">2</div>
            <div class="step-content">
                <strong>Review identified issues:</strong> The analysis results appear in the Security Analysis panel, highlighting specific vulnerabilities and risky coding patterns.
            </div>
        </div>
        
        <div class="workflow-step">
            <div class="step-number">3</div>
            <div class="step-content">
                <strong>Generate safer alternatives:</strong> Code Llama suggests more secure code alternatives that address the identified vulnerabilities.
            </div>
        </div>
        
        <div class="workflow-step">
            <div class="step-number">4</div>
            <div class="step-content">
                <strong>Track suggestions:</strong> All AI-generated code suggestions are stored in your suggestion history for later reference.
            </div>
        </div>
    </div>

    <div class="tip">
        For more targeted analysis, select specific sections of code and use <kbd>Ctrl+Alt+H</kbd> to analyze just the highlighted portion.
    </div>

    <h2>The SafeScript Analysis & Improvement Panel</h2>
    
    <div class="panel-preview">
        <div class="panel-header">SafeScript Code Analysis and Improvement Panel</div>
        <div class="panel-body">
            <p>The SafeScript panel provides an interactive workspace for analyzing and improving your code:</p>
            
            <p><span class="text-highlight">Security Analysis Section:</span> Displays detected vulnerabilities and security issues in your code.</p>
            
            <p><span class="text-highlight">Code Input Area:</span> Enter your C code here for analysis.</p>
            
            <p><span class="text-highlight">Analysis Results:</span> View the issues found in your code along with suggested improvements.</p>
            
            <p><span class="text-highlight">AI-Generated Improvements:</span> Get secure alternatives that address the identified vulnerabilities.</p>
            
            <div class="analysis-sample">
            // Security Issues:
            // - Buffer overflow vulnerability in strcpy()
            // - No bounds checking on user input
            // - Memory leak in allocated buffer
            </div>
        </div>
    </div>

    <h2>Key Features</h2>
    <div class="grid">
        <div class="feature-item">
            <div class="feature-title">Security Analysis</div>
            <p>Scan your code for potential security vulnerabilities and get detailed remediation advice.</p>
            <p>Use <kbd>Ctrl+Alt+R</kbd> to run analysis on entire file</p>
            <p>Use <kbd>Ctrl+Alt+H</kbd> to analyze highlighted code</p>
        </div>
        
        <div class="feature-item">
            <div class="feature-title">Code Generation</div>
            <p>Let Code Llama generate secure code snippets based on your requirements and findings from security analysis.</p>
            <p>Use <kbd>Ctrl+Alt+L</kbd> to run Code Llama</p>
            <p>Use <kbd>Ctrl+Alt+G</kbd> to generate secure code</p>
        </div>
        
        <div class="feature-item">
            <div class="feature-title">CVE Database</div>
            <p>Look up information about known vulnerabilities from the CVE database to understand potential risks.</p>
            <p>Use <kbd>Ctrl+Alt+C</kbd> to fetch CVE details</p>
        </div>
        
        <div class="feature-item">
            <div class="feature-title">AI Suggestions</div>
            <p>View, accept, or reject AI-generated code suggestions and track your improvement history.</p>
            <p>Use <kbd>Ctrl+Alt+S</kbd> to trigger AI suggestion</p>
            <p>Use <kbd>Ctrl+Alt+A</kbd> to accept code changes</p>
        </div>
    </div>

    <h2>Keyboard Shortcuts</h2>
    
    <table class="shortcut-table">
        <tr>
            <th>Action</th>
            <th>Shortcut</th>
            <th>Description</th>
        </tr>
        <tr>
            <td>Show Getting Started Panel</td>
            <td><kbd>Ctrl+Alt+M</kbd></td>
            <td>Gets you Started With Using SafeScript!</td>
        </tr>
        <tr>
            <td>Run Code Llama</td>
            <td><kbd>Ctrl+Alt+L</kbd></td>
            <td>Activate the Code Llama AI assistant</td>
        </tr>
        <tr>
            <td>Run Security Analysis</td>
            <td><kbd>Ctrl+Alt+R</kbd></td>
            <td>Analyze current file for security vulnerabilities</td>
        </tr>
        <tr>
            <td>Analyze Highlighted Code</td>
            <td><kbd>Ctrl+Alt+H</kbd></td>
            <td>Run analysis on selected code portion only</td>
        </tr>
        <tr>
            <td>Trigger AI Suggestion</td>
            <td><kbd>Ctrl+Alt+S</kbd></td>
            <td>Request AI to provide code improvement suggestions</td>
        </tr>
        <tr>
            <td>Accept Code Changes</td>
            <td><kbd>Ctrl+Alt+A</kbd></td>
            <td>Apply suggested code improvements</td>
        </tr>
        <tr>
            <td>Toggle Assistant Sidebar</td>
            <td><kbd>Ctrl+Alt+D</kbd></td>
            <td>Show/hide the SafeScript sidebar</td>
        </tr>
        <tr>
            <td>Fetch CVE Details</td>
            <td><kbd>Ctrl+Alt+C</kbd></td>
            <td>Search the CVE database for vulnerability information</td>
        </tr>
        <tr>
            <td>Accept AI Suggestion</td>
            <td><kbd>Ctrl+Alt+1</kbd></td>
            <td>Accept the current AI suggestion</td>
        </tr>
        <tr>
            <td>Reject AI Suggestion</td>
            <td><kbd>Ctrl+Alt+2</kbd></td>
            <td>Discard the current AI suggestion</td>
        </tr>
    </table>

    <h2>Analysis Panel Deep Dive</h2>
    
    <div class="card">
        <h3>How the Analysis Panel Works</h3>
        <p>The SafeScript Code Analysis and Improvement Panel is where most of your security work happens:</p>
        
        <ol>
            <li><strong>Security Analysis Section:</strong> This area displays detected vulnerabilities in easy-to-understand language, focusing on high-risk issues first.</li>
            <li><strong>Code Input:</strong> Paste your C code or use the keyboard shortcut to analyze your current file.</li>
            <li><strong>Analysis Results:</strong> View the detailed findings, including specific line numbers and vulnerability descriptions.</li>
            <li><strong>AI-Generated Improvements:</strong> Code Llama suggests secure alternatives that address each identified vulnerability.</li>
            <li><strong>Suggestion Management:</strong> Add promising code improvements to your suggestion history for later reference or implementation.</li>
        </ol>
        
        <p>The panel performs static analysis on your code to detect:</p>
        <ul>
            <li>Buffer overflow vulnerabilities</li>
            <li>Memory leaks</li>
            <li>Use-after-free issues</li>
            <li>Format string vulnerabilities</li>
            <li>Integer overflow/underflow risks</li>
            <li>Injection vulnerabilities</li>
            <li>And many other common security issues</li>
        </ul>
    </div>

    <div class="tip">
        The Analysis Panel works best with C code but can also provide security insights for C++, JavaScript, Python, and other languages. Language-specific vulnerabilities are automatically detected based on the code syntax.
    </div>

    <h2>Views & Panels</h2>
    <p>SafeScript provides multiple views to help you work with its features:</p>
    
    <div class="panel-preview">
        <div class="panel-header">Available SafeScript Views</div>
        <div class="panel-body">
            <p><span class="text-highlight">Code Llama Generated Code:</span> View AI-generated code suggestions with security improvements</p>
            
            <p><span class="text-highlight">Security Analysis:</span> Results of security scans on your code with detailed vulnerability descriptions</p>
            
            <p><span class="text-highlight">AI Suggestions History:</span> Track your history of AI suggestions and implementation status</p>
            
            <p><span class="text-highlight">CVE Details:</span> Information about Common Vulnerabilities and Exposures from the CVE database</p>
        </div>
    </div>

    <div class="tip">
        You can toggle the SafeScript sidebar using <kbd>Ctrl+Alt+D</kbd> to give yourself more screen space when needed. This hides the panels temporarily without closing your current analysis session.
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
        SafeScript: Making secure code development easier and more accessible
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