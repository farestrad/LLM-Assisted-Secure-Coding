import * as fs from 'fs';
import { exec } from 'child_process';
import * as vscode from 'vscode';

// Function to handle C code testing
export async function runCTests(code: string, securityAnalysisProvider: any) {
    // Check if there's an open workspace folder
    if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
        vscode.window.showErrorMessage("No workspace folder is open. Please open a workspace to run tests.");
        return;
    }

    // Define the file path based on the first workspace folder
    const tempFilePath = vscode.workspace.workspaceFolders[0].uri.fsPath + '/temp_test_code.c';

    // Wrap the generated code with unit tests
    const testCode = `
#include <stdio.h>
#include <assert.h>

// Generated code
${code}

// Unit test function
void run_tests() {
    // Example assertions (replace with real test cases)
    assert(your_function(1) == expected_result);
    printf("Test passed.\\n");
    assert(your_function(2) == another_expected_result);
    printf("All tests passed!\\n");
}

int main() {
    run_tests();
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
