import * as fs from 'fs';
import { exec } from 'child_process';
import * as vscode from 'vscode';

export async function runCTests(code: string, securityAnalysisProvider: any) {
    // Check if there's an open workspace folder
    if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
        vscode.window.showErrorMessage("No workspace folder is open. Please open a workspace to run tests.");
        return;
    }

    // Define the file path based on the first workspace folder
    const tempFilePath = vscode.workspace.workspaceFolders[0].uri.fsPath + '/temp_test_code.c';

    // Security checks
    const securityIssues = analyzeCodeForSecurityIssues(code);
    if (securityIssues.length > 0) {
        securityAnalysisProvider.updateSecurityAnalysis(securityIssues);
        return; // Stop here if there are security issues
    }

    // Wrap the generated code with a main function for testing
    const testCode = `
#include <stdio.h>
#include <assert.h>

${code}

int main() {
    // Test code runs here (add tests if needed)
    return 0;
}
`;

    // Save the test code to a file
    fs.writeFileSync(tempFilePath, testCode);

    // Compile the C code
    exec(`gcc ${tempFilePath} -o temp_test_code`, (compileError, stdout, stderr) => {
        if (compileError) {
            securityAnalysisProvider.updateSecurityAnalysis(['Compilation failed: ' + stderr]);
            return;
        }

        // Run the compiled code if compilation was successful
        exec(`./temp_test_code`, (runError, runOutput, runErr) => {
            const results = runError ? `Test execution failed: ${runErr}` : runOutput;
            securityAnalysisProvider.updateSecurityAnalysis([results.trim()]);
        });
    });
}

// Analyze code for buffer overflow risks and other security issues
function analyzeCodeForSecurityIssues(code: string): string[] {
    const issues = [];

    // Check for risky functions
    const riskyFunctions = ['strcpy', 'gets', 'sprintf'];
    riskyFunctions.forEach(func => {
        const regex = new RegExp(`\\b${func}\\b`);
        if (regex.test(code)) {
            issues.push(`Warning: Use of ${func} detected. Consider using safer alternatives (e.g., strncpy, fgets, snprintf).`);
        }
    });

    // Check for buffers without bounds checking
    const bufferRegex = /\bchar\s+\w+\[(\d+)\];/g;
    let match;
    while ((match = bufferRegex.exec(code)) !== null) {
        const bufferName = match[0];
        const bufferDeclaration = match[0];
        if (!new RegExp(`sizeof\\(${bufferName}\\)`).test(code)) {
            issues.push(`Warning: Buffer ${bufferDeclaration} does not include bounds checking. Use sizeof(${bufferName}) to prevent overflow.`);
        }
    }

    // Check for safer memory allocation (optional)
    if (!/\b(malloc|calloc)\b/.test(code) && /\bchar\s+\w+\[\d+\];/.test(code)) {
        issues.push("Consider using dynamic memory allocation (malloc or calloc) for buffers to handle variable input sizes.");
    }

    return issues;
}
