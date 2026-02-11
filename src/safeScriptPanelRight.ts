import * as vscode from 'vscode';
import { AISuggestionHistoryProvider } from './AISuggestionHistoryProvider';

export class SafeScriptPanelRight {
    public static panel: vscode.WebviewPanel | undefined;
    private static currentIssues: string = "No security issues detected.";
    private static aiSuggestionHistoryProvider: AISuggestionHistoryProvider | undefined;

    public static createOrShow(context: vscode.ExtensionContext, aiSuggestionHistoryProvider?: AISuggestionHistoryProvider) {
        // Store the provider reference if provided
        if (aiSuggestionHistoryProvider) {
            SafeScriptPanelRight.aiSuggestionHistoryProvider = aiSuggestionHistoryProvider;
        }

        if (SafeScriptPanelRight.panel) {
            SafeScriptPanelRight.panel.reveal(vscode.ViewColumn.Two);
            return;
        }

        SafeScriptPanelRight.panel = vscode.window.createWebviewPanel(
            'safeScriptPanelRight',
            'SafeScript Code Analysis and Improvement Panel',
            vscode.ViewColumn.Two,
            { enableScripts: true, retainContextWhenHidden: true }
        );

        SafeScriptPanelRight.panel.webview.html = SafeScriptPanelRight.getHtmlContent();
        
        SafeScriptPanelRight.panel.onDidDispose(() => {
            SafeScriptPanelRight.panel = undefined;
        }, null, context.subscriptions);
        
        SafeScriptPanelRight.panel.webview.onDidReceiveMessage(async message => {
            switch (message.command) {
                case 'getIssues':
                    SafeScriptPanelRight.postMessage({
                        command: 'updateIssues',
                        issues: SafeScriptPanelRight.currentIssues
                    });
                    break;
                case 'analyzeCode':
                    const result = await vscode.commands.executeCommand(
                        'extension.analyzeCodeFromRightPanel', 
                        message.code
                    );
                    SafeScriptPanelRight.postMessage({
                        command: 'analysisComplete',
                        result: result
                    });
                    break;
                case 'generateCode':
                    // For code generation mode, we'll just pass the prompt to the LLM directly
                    SafeScriptPanelRight.postMessage({
                        command: 'generationRequested',
                        prompt: message.prompt
                    });
                    break;
                case 'improvedCodeGenerated':
                    // Add improved code to the AI Suggestion History
                    if (SafeScriptPanelRight.aiSuggestionHistoryProvider) {
                        SafeScriptPanelRight.aiSuggestionHistoryProvider.addAISuggestion(
                            message.improvedCode, 
                            message.originalCode
                        );
                        vscode.window.showInformationMessage('Improved code added to AI Suggestion History.');
                    }
                    break;
            }
        }, undefined, context.subscriptions);
        
        context.subscriptions.push(SafeScriptPanelRight.panel);
    }

    public static postMessage(message: any): void {
        if (SafeScriptPanelRight.panel) {
            if (message.command === 'updateIssues') {
                SafeScriptPanelRight.currentIssues = message.issues;
            }
            SafeScriptPanelRight.panel.webview.postMessage(message);
        }
    }

    private static getHtmlContent(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SafeScript Security and Improvement Panel</title>
  <style>
    :root {
      --bg-color: #1e1e1e;
      --card-bg: #252526;
      --text-color: #cccccc;
      --text-muted: #888888;
      --border-color: #3d3d3d;
      --primary: #0e639c;
      --primary-light: #1177bb;
      --secondary: #3a8547;
      --accent: #ce9178;
      --error: #f14c4c;
      --status: #3794ff;
    }
    body {
      font-family: -apple-system, system-ui, sans-serif;
      font-size: 13px;
      background: var(--bg-color);
      color: var(--text-color);
      margin: 0;
      padding: 12px;
      height: 100vh;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .card {
      background: var(--card-bg);
      border-radius: 4px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .card-header {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-color);
      font-weight: 500;
    }
    .card-body {padding: 12px;}
    #issuesContainer {
      background: rgba(206, 145, 120, 0.1);
      color: var(--accent);
      padding: 10px;
      border-left: 3px solid var(--accent);
      border-radius: 2px;
      white-space: pre-wrap;
      margin-bottom: 12px;
    }
    #statusIndicator {
      background: rgba(55, 148, 255, 0.1);
      color: var(--status);
      padding: 10px;
      margin-bottom: 12px;
      border-left: 3px solid var(--status);
      border-radius: 2px;
      display: none;
      animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
      0% {opacity: 0.8;}
      50% {opacity: 1;}
      100% {opacity: 0.8;}
    }
    #chatContainer {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 12px;
      padding: 12px;
    }
    #inputContainer {
      height: 140px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      padding: 12px;
    }
    #messageInput {
      flex: 1;
      resize: none;
      padding: 10px;
      border: 1px solid var(--border-color);
      border-radius: 4px;
      background: rgba(40, 40, 40, 0.5);
      color: var(--text-color);
      font-family: inherit;
    }
    #messageInput:focus {
      outline: none;
      border-color: var(--primary);
    }
    #buttonContainer {
      display: flex;
      gap: 10px;
      justify-content: space-between;
      align-items: center;
    }
    .c-code-info {color: var(--text-muted); flex: 1;}
    .button {
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
      border: none;
      transition: all 0.2s;
    }
    #sendButton {
      background: var(--primary);
      color: white;
    }
    #sendButton:hover {background: var(--primary-light);}
    #sendButton:disabled {opacity: 0.6; cursor: not-allowed;}
    #clearButton {
      background: transparent;
      border: 1px solid var(--border-color);
      color: var(--text-color);
    }
    #clearButton:hover {background: rgba(255,255,255,0.1);}
    .bubble {
      max-width: 80%;
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 13px;
      white-space: pre-wrap;
    }
    .user {
      background: rgba(14, 99, 156, 0.2);
      color: #9cdcfe;
      align-self: flex-end;
      border-bottom-right-radius: 2px;
    }
    .bot {
      background: rgba(58, 133, 71, 0.2);
      color: #b5cea8;
      align-self: flex-start;
      border-bottom-left-radius: 2px;
    }
    .status {
      background: rgba(55, 148, 255, 0.1);
      color: var(--status);
      align-self: flex-start;
      font-style: italic;
      padding: 6px 12px;
    }
    code {
      font-family: monospace;
      background: rgba(0,0,0,0.2);
      padding: 2px 4px;
      border-radius: 2px;
    }
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: var(--text-muted);
      text-align: center;
      padding: 20px;
    }
    .empty-state-icon {font-size: 32px; margin-bottom: 12px;}
    ::-webkit-scrollbar {width: 6px; height: 6px;}
    ::-webkit-scrollbar-track {background: transparent;}
    ::-webkit-scrollbar-thumb {
      background: #555;
      border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {background: #666;}
    .error-message {
      color: var(--error);
      background: rgba(241, 76, 76, 0.1);
      padding: 10px;
      border-radius: 2px;
      display: none;
    }
    .hidden {display: none;}
    .action-buttons {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }
    .action-button {
      background: transparent;
      border: 1px solid var(--border-color);
      color: var(--text-color);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 11px;
      cursor: pointer;
    }
    .action-button:hover {
      background: rgba(255,255,255,0.1);
    }
    .action-button.primary {
      background: var(--secondary);
      border-color: var(--secondary);
      color: white;
    }
    .action-button.primary:hover {
      background: #429652;
    }
    /* Toggle switch styles */
    .toggle-container {
      display: flex;
      justify-content: center;
      align-items: center;
      margin-bottom: 12px;
      padding: 8px;
      background: var(--card-bg);
      border-radius: 4px;
    }
    .toggle-option {
      padding: 6px 12px;
      border-radius: 4px;
      font-size: 12px;
      cursor: pointer;
      text-align: center;
      flex: 1;
      transition: all 0.2s;
    }
    .toggle-option.active {
      background: var(--primary);
      color: white;
    }
    .toggle-option:not(.active) {
      background: transparent;
      color: var(--text-color);
    }
    .toggle-option:not(.active):hover {
      background: rgba(255,255,255,0.05);
    }
  </style>
</head>
<body>
  <div class="toggle-container">
    <div id="analyzeToggle" class="toggle-option active">Analyze & Improve</div>
    <div id="generateToggle" class="toggle-option">Generate Code</div>
  </div>

  <div id="statusIndicator" style="visibility: hidden;"></div>
  
  <div id="chatContainer" class="card">
    <div class="empty-state">
      <div class="empty-state-icon">💻</div>
      <h3>Welcome to SafeScript</h3>
      <p id="emptyStateText">Enter C code below to analyze and improve security.</p>
    </div>
  </div>
  
  <div id="inputContainer" class="card">
    <textarea id="messageInput" placeholder="Enter your C code here..."></textarea>
    <div id="error-message" class="error-message">Invalid C code. Please check syntax.</div>
    <div id="buttonContainer">
      <div id="inputInfo" class="c-code-info">Enter valid C code for best results</div>
      <button id="clearButton" class="button">Clear</button>
      <button id="sendButton" class="button">Analyze & Improve</button>
    </div>
  </div>
  
  <script>
    const vscode = acquireVsCodeApi();
    let detectedIssues = "No security issues detected.";
    let isProcessing = false;
    let currentUserCode = "";
    let currentImprovedCode = "";
    let isGenerateMode = false;
    
    const issuesContainer = document.getElementById('issuesContainer');
    const statusIndicator = document.getElementById('statusIndicator');
    const chatContainer = document.getElementById('chatContainer');
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const clearButton = document.getElementById('clearButton');
    const errorMessage = document.getElementById('error-message');
    const emptyState = document.querySelector('.empty-state');
    const emptyStateText = document.getElementById('emptyStateText');
    const inputInfo = document.getElementById('inputInfo');
    const analyzeToggle = document.getElementById('analyzeToggle');
    const generateToggle = document.getElementById('generateToggle');

    // Toggle mode handlers
    analyzeToggle.addEventListener('click', () => {
      if (isGenerateMode) {
        switchToAnalyzeMode();
      }
    });

    generateToggle.addEventListener('click', () => {
      if (!isGenerateMode) {
        switchToGenerateMode();
      }
    });

    function switchToAnalyzeMode() {
      isGenerateMode = false;
      analyzeToggle.classList.add('active');
      generateToggle.classList.remove('active');
      sendButton.textContent = 'Analyze & Improve';
      messageInput.placeholder = 'Enter your C code here...';
      emptyStateText.textContent = 'Enter C code below to analyze and improve security.';
      inputInfo.textContent = 'Enter valid C code for best results';
      errorMessage.textContent = 'Invalid C code. Please check syntax.';
    }

    function switchToGenerateMode() {
      isGenerateMode = true;
      generateToggle.classList.add('active');
      analyzeToggle.classList.remove('active');
      sendButton.textContent = 'Generate Code';
      messageInput.placeholder = 'Describe the C code you want to generate...';
      emptyStateText.textContent = 'Describe the C code you want to generate.';
      inputInfo.textContent = 'Be specific about the functionality you need';
      errorMessage.textContent = 'Please provide a clear description of the code to generate.';
    }

    window.addEventListener('message', event => {
      const message = event.data;
      
      if (message.command === 'updateIssues') {
        detectedIssues = message.issues || "No security issues detected.";
        issuesContainer.textContent = detectedIssues;
      }
      
      if (message.command === 'analysisStatus') {
        statusIndicator.style.display = 'block';
        statusIndicator.textContent = message.status;
      }
      
      if (message.command === 'analysisComplete') {
        statusIndicator.style.display = 'none';
        if (isProcessing && !isGenerateMode) {
          generateImprovedCode();
        }
      }

      if (message.command === 'generationRequested') {
        if (isProcessing && isGenerateMode) {
          generateNewCode(message.prompt);
        }
      }
    });

    window.addEventListener('load', () => {
      vscode.postMessage({ command: 'getIssues' });
    });

    function appendBubble(type, text, showActions = false, isGenerated = false) {
      if (emptyState && !emptyState.classList.contains('hidden')) {
        emptyState.classList.add('hidden');
      }
      
      const wrapper = document.createElement('div');
      wrapper.style.display = 'flex';
      wrapper.style.flexDirection = 'column';
      wrapper.style.alignSelf = type === 'user' ? 'flex-end' : 'flex-start';
      wrapper.style.maxWidth = '80%';
      
      const bubble = document.createElement('div');
      bubble.classList.add('bubble', type);
      bubble.textContent = text;
      wrapper.appendChild(bubble);
      
      // Only show "Add to Suggestion History" button for improved code (not generated code)
      if (showActions && type === 'bot' && !isGenerated) {
        const actionButtons = document.createElement('div');
        actionButtons.classList.add('action-buttons');
        
        const addToHistoryBtn = document.createElement('button');
        addToHistoryBtn.classList.add('action-button', 'primary');
        addToHistoryBtn.textContent = 'Add to Suggestion History';
        addToHistoryBtn.addEventListener('click', () => {
          // Send improved code to extension to add to history
          vscode.postMessage({
            command: 'improvedCodeGenerated',
            improvedCode: text,
            originalCode: currentUserCode
          });
          addToHistoryBtn.disabled = true;
          addToHistoryBtn.textContent = 'Added to History';
        });
        
        const copyBtn = document.createElement('button');
        copyBtn.classList.add('action-button');
        copyBtn.textContent = 'Copy Code';
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(text).then(() => {
            copyBtn.textContent = 'Copied!';
            setTimeout(() => {
              copyBtn.textContent = 'Copy Code';
            }, 2000);
          });
        });
        
        // Only add the "Add to Suggestion History" button for improved code
        if (!isGenerated) {
          actionButtons.appendChild(addToHistoryBtn);
        }
        actionButtons.appendChild(copyBtn);
        wrapper.appendChild(actionButtons);
      } else if (showActions && type === 'bot' && isGenerated) {
        // For generated code, only show the copy button
        const actionButtons = document.createElement('div');
        actionButtons.classList.add('action-buttons');
        
        const copyBtn = document.createElement('button');
        copyBtn.classList.add('action-button');
        copyBtn.textContent = 'Copy Code';
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(text).then(() => {
            copyBtn.textContent = 'Copied!';
            setTimeout(() => {
              copyBtn.textContent = 'Copy Code';
            }, 2000);
          });
        });
        
        const analyzeBtn = document.createElement('button');
        analyzeBtn.classList.add('action-button', 'primary');
        analyzeBtn.textContent = 'Analyze This Code';
        analyzeBtn.addEventListener('click', () => {
          switchToAnalyzeMode();
          messageInput.value = text;
          // Focus on the send button to encourage user to click it
          sendButton.focus();
        });
        
        actionButtons.appendChild(analyzeBtn);
        actionButtons.appendChild(copyBtn);
        wrapper.appendChild(actionButtons);
      }
      
      chatContainer.appendChild(wrapper);
      chatContainer.scrollTop = chatContainer.scrollHeight;
      return bubble;
    }
    
    function removeLastBubbleIfLoading() {
      const statusBubbles = chatContainer.querySelectorAll('.bubble.status');
      if (statusBubbles.length > 0) {
        const lastStatusBubble = statusBubbles[statusBubbles.length - 1];
        if (lastStatusBubble.textContent.includes('Loading') || 
            lastStatusBubble.textContent.includes('Analyzing') || 
            lastStatusBubble.textContent.includes('Generating')) {
          chatContainer.removeChild(lastStatusBubble.parentElement);
        }
      }
    }
    
    function isLikelyCCode(code) {
      if (isGenerateMode) {
        // In generate mode, we accept any input as a prompt
        return true;
      }
      
      if (code.includes('#include') || 
          /\b(int|char|float|double|void|struct|if|for|while|return|malloc|free|printf)\b/.test(code)) {
        return true;
      }
      if (code.includes('<html') || code.includes('<script>') || /^\s*\{\s*"/.test(code)) {
        return false;
      }
      return true;
    }

    sendButton.addEventListener('click', async () => {
      const userInput = messageInput.value.trim();
      if (!userInput) { return; }
      
      errorMessage.style.display = 'none';
      
      if (!isLikelyCCode(userInput) && !isGenerateMode) {
        errorMessage.style.display = 'block';
        return;
      }
      
      isProcessing = true;
      sendButton.disabled = true;
      
      // Store the original user code/prompt
      currentUserCode = userInput;
      
      appendBubble('user', userInput);
      messageInput.value = '';
      
      if (isGenerateMode) {
        appendBubble('status', '✏️ Generating C code...');
        
        // For code generation, we'll handle it directly
        generateNewCode(userInput);
      } else {
        appendBubble('status', '🔍 Analyzing code...');
        
        // For analysis, send to VSCode extension
        vscode.postMessage({
          command: 'analyzeCode',
          code: userInput
        });
      }
    });
    
    clearButton.addEventListener('click', () => {
      messageInput.value = '';
      messageInput.focus();
    });
    
    async function generateImprovedCode() {
      removeLastBubbleIfLoading();
      appendBubble('status', '✨ Generating improved code with DeepSeek...');
      
      try {
        const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ${process.env.DEEPSEEK_API_KEY}'
          },
          body: JSON.stringify({ 
            model: 'deepseek-coder',
            messages: [
              {
                role: 'system',
                content: 'Only provide the C code with no additional explanation, comments, NO extra text, and do not write the letter c on top, do not generate backticks on top or below the c code, just output pure c code.'
              },
              {
                role: 'user',
                content: \`Improve the following C code to address these security issues:
    Security Issues: \${detectedIssues}
    Function Code: \${currentUserCode}\`
              }
            ]
          })
        });
        
        if (!response.ok) { 
          throw new Error('Error generating improved code'); 
        }
        
        const data = await response.json();
        removeLastBubbleIfLoading();
        
        currentImprovedCode = data.choices?.[0]?.message?.content || 'No reply received';
        appendBubble('bot', currentImprovedCode, true, false);
      } catch (error) {
        removeLastBubbleIfLoading();
        appendBubble('bot', '❌ Error: ' + error.message);
      } finally {
        sendButton.disabled = false;
        isProcessing = false;
      }
    }
    
    async function generateNewCode(prompt) {
      removeLastBubbleIfLoading();
      appendBubble('status', '✏️ Generating C code with DeepSeek...');
      
      try {
        const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ${process.env.DEEPSEEK_API_KEY}'
          },
          body: JSON.stringify({ 
            model: 'deepseek-coder',
            messages: [
              {
                role: 'system',
                content: 'Generate the entire function of C code based on the following description. Only provide the C code with no additional explanation, comments, NO extra text, and do not write the letter c on top, do not generate backticks on top or below the c code, just output pure c code.'
              },
              {
                role: 'user',
                content: prompt
              }
            ]
          })
        });
        
        if (!response.ok) { 
          throw new Error('Error generating code'); 
        }
        
        const data = await response.json();
        removeLastBubbleIfLoading();
        
        const generatedCode = data.choices?.[0]?.message?.content || 'No reply received';
        appendBubble('bot', generatedCode, true, true);
      } catch (error) {
        removeLastBubbleIfLoading();
        appendBubble('bot', '❌ Error: ' + error.message);
      } finally {
        sendButton.disabled = false;
        isProcessing = false;
      }
    }
    
    messageInput.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !sendButton.disabled) {
        sendButton.click();
        e.preventDefault();
      }
    });
  </script>
</body>
</html>`;
    }

    public static dispose() {
        if (SafeScriptPanelRight.panel) {
            SafeScriptPanelRight.panel.dispose();
        }
    }
}