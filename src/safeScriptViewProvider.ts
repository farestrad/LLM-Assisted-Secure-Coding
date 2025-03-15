import * as vscode from 'vscode';

export class SafeScriptViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = 'safescriptPanel';
  private _view?: vscode.WebviewView;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      // Enable scripts in the webview
      enableScripts: true,
      localResourceRoots: [this._extensionUri]
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
  }

  private _getHtmlForWebview(webview: vscode.Webview): string {
    // You can further enhance this HTML based on your needs.
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SafeScript Sidebar</title>
  <style>
    body {
      font-family: sans-serif;
      padding: 10px;
    }
  </style>
</head>
<body>
  <h1>SafeScript Sidebar</h1>
  <p>This is your dedicated SafeScript view in the sidebar.</p>
</body>
</html>`;
  }
}
