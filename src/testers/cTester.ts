import * as fs from 'fs';
import { exec } from 'child_process';
import * as vscode from 'vscode';
import { promisify } from 'util';

const execPromise = promisify(exec);

// Define the file path, with a fallback to `/tmp` if no workspace is open
const tempFilePath = vscode.workspace.workspaceFolders
    ? `${vscode.workspace.workspaceFolders[0].uri.fsPath}/temp_test_code.c`
    : `/tmp/temp_test_code.c`; // Fallback to a system temp directory

export async function runCTests(code: string, securityAnalysisProvider: any) {
    // Run security checks
    const securityIssues = analyzeCodeForSecurityIssues(code);
    if (securityIssues.length > 0) {
        securityAnalysisProvider.updateSecurityAnalysis(securityIssues);
        return;
    }

    // Wrap the generated code with a main function for testing
    const testCode = `
#include <stdio.h>
#include <assert.h>

${code}

int main() {
    return 0;
}
`;

    try {
        // Write test code to a file
        fs.writeFileSync(tempFilePath, testCode);
        console.log(`Code written to ${tempFilePath}`);

        await compileCode(tempFilePath, securityAnalysisProvider);
        await executeCompiledCode(securityAnalysisProvider);
    } catch (error) {
        const err = error as Error; // Cast 'error' to 'Error' type
        console.error("Error in runCTests:", err.message);
        securityAnalysisProvider.updateSecurityAnalysis([`Error during testing: ${err.message}`]);
    }
}

// Compile the C code and handle any compilation errors
async function compileCode(filePath: string, securityAnalysisProvider: any): Promise<void> {
    try {
        const { stderr } = await execPromise(`gcc ${filePath} -o temp_test_code`);
        if (stderr) {
            throw new Error(stderr);
        }
        console.log("Compilation successful");
    } catch (error) {
        const err = error as Error; // Cast 'error' to 'Error' type
        console.error("Compilation error:", err.message);
        securityAnalysisProvider.updateSecurityAnalysis([`Compilation failed: ${err.message}`]);
        throw err;
    }
}

// Execute the compiled code and handle any runtime errors
async function executeCompiledCode(securityAnalysisProvider: any): Promise<void> {
    try {
        const { stdout, stderr } = await execPromise(`./temp_test_code`);
        const results = stderr ? `Execution failed: ${stderr}` : stdout;
        console.log("Execution results:", results.trim());
        securityAnalysisProvider.updateSecurityAnalysis([results.trim()]);
    } catch (error) {
        const err = error as Error; // Cast 'error' to 'Error' type
        console.error("Execution error:", err.message);
        securityAnalysisProvider.updateSecurityAnalysis([`Test execution failed: ${err.message}`]);
    }
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
    const bufferRegex = /\bchar\s+(\w+)\[(\d+)\];/g;
    let match;
    while ((match = bufferRegex.exec(code)) !== null) {
        const bufferName = match[1];
        if (!new RegExp(`sizeof\\(${bufferName}\\)`).test(code)) {
            issues.push(`Warning: Buffer ${bufferName} does not include bounds checking. Use sizeof(${bufferName}) to prevent overflow.`);
        }
    }

    // Check for absence of dynamic memory allocation
    if (!/\b(malloc|calloc)\b/.test(code) && /\bchar\s+\w+\[\d+\];/.test(code)) {
        issues.push("Consider using dynamic memory allocation (malloc or calloc) for buffers to handle variable input sizes.");
    }

    return issues;
}

// Example call to runCTests for quick testing
// Uncomment the following code to test `runCTests` directly
// const exampleCode = `
// #include <string.h>
//
// void example() {
//     char buffer[10];
//     strcpy(buffer, "This is too long");
// }
// `;
// runCTests(exampleCode, {
//     updateSecurityAnalysis: (issues: string[]) => {
//         console.log("Security Analysis Output:", issues);
//     }
// });

