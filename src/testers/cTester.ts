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
    /*
    const testCode = `
#include <stdio.h>
#include <assert.h>

${code}

int main() {
    return 0;
}
`;
*/
const testCode = `
${code}
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

     // Check for insecure random number generation
     const randomPattern = /\b(rand|srand)\b/;
     if (randomPattern.test(code)) {
         issues.push("Warning: Insecure random number generation detected. Consider using a secure alternatives.");
     }
 
     // Check for unchecked return values of memory allocation functions
     const allocationFunctions = ['malloc', 'calloc', 'realloc'];
     allocationFunctions.forEach(func => {
         const regex = new RegExp(`\\b${func}\\b`);
         if (regex.test(code) && !new RegExp(`if\\s*\\(\\s*${func}`).test(code)) {
             issues.push(`Warning: Unchecked return value of ${func} detected. Ensure memory allocation success.`);
         }
     });


     ////////////////////////////////////
     // 1. Check for potentially insufficient memory allocation with malloc
    const mallocPattern = /\bmalloc\s*\(\s*(\d+)\s*\)/g;
    while ((match = mallocPattern.exec(code)) !== null) {
        const allocatedSize = parseInt(match[1], 10);
        if (allocatedSize < 100) {  // Adjust threshold as needed
            issues.push(`Warning: Potentially insufficient memory allocation with malloc at position ${match.index}. Ensure buffer size is adequate.`);
        }
    }

     ///////////////////////////////////
 
     // Check for command injection vulnerabilities
     const commandInjectionPattern = /system\(|popen\(|exec\(|fork\(|wait\(|systemp\(/;
     if (commandInjectionPattern.test(code)) {
         issues.push("Warning: Possible command injection vulnerability detected. Avoid using system calls with user input.");
     }
 
     // Check for path traversal vulnerabilities
     const pathTraversalPattern = /\.\.\//;
     if (pathTraversalPattern.test(code)) {
         issues.push("Warning: Potential Path Traversal vulnerability detected. Avoid using relative paths with user input.");
     }
 
     // Check for improper authentication handling
     const authPattern = /\b(==|!=)\s*["'].*["']/;
     if (authPattern.test(code)) {
         issues.push("Warning: Improper authentication handling detected. Avoid using string comparison for sensitive data.");
     }
 
     // Check for insecure cryptographic storage
     const cryptoPattern = /\bMD5\b|\bSHA1\b/;
     if (cryptoPattern.test(code)) {
         issues.push("Warning: Insecure cryptographic storage detected. Avoid using weak hashing algorithms.");
     }
 
     // Check for race conditions in file access
     const racePattern = /\b(fopen|fwrite|fread|fclose)\b/;
     if (racePattern.test(code)) {
         issues.push("Warning: Improper file access detected. Ensure proper file locking.");
     }
 
     // Check for improper error handling and logging
     const errorPattern = /\bprintf\(|fprintf\(|stderr|strerror\(/;
     if (errorPattern.test(code)) {
         issues.push("Warning: Improper error handling and logging detected. Ensure proper error messages and logging.");
     }
     
     // Check for improper inputs validation
    const inputPattern = /\batoi\(|atol\(|atof\(|gets\(|scanf\(/;
    if (inputPattern.test(code)) {
        issues.push("Warning: Improper input validation detected. Ensure proper input validation and sanitization.");
    }

    // Check for hard coded credentials
    const hardCodedPattern = /\b(password|secret|apikey)\s*=\s*["'].*["']/;
    if (hardCodedPattern.test(code)) {
        issues.push("Warning: Hardcoded credentials detected. Avoid hardcoding credentials in the code.");
    }

    // Check for improper privilege management
    const privilegePattern = /\bsetuid\(|setgid\(|seteuid\(|setegid\(/;
    if (privilegePattern.test(code)) {
        issues.push("Warning: Improper privilege management detected. Avoid using setuid, setgid, seteuid, and setegid.");
    }

    // Check for improper session management
    const sessionPattern = /\bsession_start\(|session_id\(/;
    if (sessionPattern.test(code)) {
        issues.push("Warning: Improper session management detected. Ensure proper session handling.");
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