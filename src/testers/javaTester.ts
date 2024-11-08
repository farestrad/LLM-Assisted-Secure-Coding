import * as fs from 'fs';
import { exec } from 'child_process';
import * as vscode from 'vscode';

export async function runJavaTests(code: string, securityAnalysisProvider: any) {
    // Ensure there's an open workspace folder
    if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
        vscode.window.showErrorMessage("No workspace folder is open. Please open a workspace to run tests.");
        return;
    }

    // Define the file path based on the first workspace folder
    const workspacePath = vscode.workspace.workspaceFolders[0].uri.fsPath;
    const tempFilePath = `${workspacePath}/TempTestClass.java`;

    // Save the generated code to a file
    try {
        fs.writeFileSync(tempFilePath, code);
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to write Java test file: ${error}`);
        return;
    }

    // Compile the Java file
    exec(`javac ${tempFilePath}`, (compileError, stdout, stderr) => {
        if (compileError) {
            securityAnalysisProvider.updateSecurityAnalysis(['Java compilation failed: ' + stderr]);
            return;
        }

        // Run the Java class if compilation was successful
        exec(`java -cp ${workspacePath} TempTestClass`, (runError, runOutput, runErr) => {
            const results = runError ? `Java execution failed: ${runErr}` : runOutput;
            securityAnalysisProvider.updateSecurityAnalysis([results.trim()]);
        });
    });
}
