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

      //  await compileCode(tempFilePath, securityAnalysisProvider);
       // await executeCompiledCode(securityAnalysisProvider);
    } catch (error) {
        const err = error as Error; // Cast 'error' to 'Error' type
        console.error("Error in runCTests:", err.message);
        securityAnalysisProvider.updateSecurityAnalysis([`Error during testing: ${err.message}`]);
    }
}

// Compile the C code and handle any compilation errors
/*
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
    */

// Main analysis function
function analyzeCodeForSecurityIssues(code: string): string[] {
    const issues: string[] = [];
    
    // Perform different categories of checks
    issues.push(...checkBufferOverflowVulnerabilities(code));
    issues.push(...checkRaceConditionVulnerabilities(code));
    issues.push(...checkOtherVulnerabilities(code));
    issues.push(...checkHeapOverflowVulnerabilities(code));
    issues.push(...analyzeCodeForPlaintextPasswords(code));

    return issues;
}

// Buffer Overflow Vulnerability Checks
function checkBufferOverflowVulnerabilities(code: string): string[] {
    const issues: string[] = [];
    let match;

    // Check for risky functions
    const riskyFunctions = ['strcpy', 'gets', 'sprintf'];
    riskyFunctions.forEach(func => {
        const regex = new RegExp(`\\b${func}\\b`);
        if (regex.test(code)) {
            issues.push(`Warning: Use of ${func} detected. Consider using safer alternatives (e.g., strncpy, fgets, snprintf).`);
        }
    });

    // Check for buffer allocations without bounds checking
    const bufferRegex = /\bchar\s+(\w+)\[(\d+)\];/g;
    while ((match = bufferRegex.exec(code)) !== null) {
        const bufferName = match[1];
        if (!new RegExp(`sizeof\\(${bufferName}\\)`).test(code)) {
            issues.push(`Warning: Buffer ${bufferName} does not include bounds checking. Use sizeof(${bufferName}) to prevent overflow.`);
        }
    }

    // Check for malloc calls with insufficient size
    const mallocPattern = /\bmalloc\s*\(\s*(\d+)\s*\)/g;
    while ((match = mallocPattern.exec(code)) !== null) {
        const allocatedSize = parseInt(match[1], 10);
        if (allocatedSize < 100) {
            issues.push(`Warning: Potentially insufficient memory allocation with malloc at position ${match.index}. Ensure buffer size is adequate.`);
        }
    }



        // Check for small buffer declarations that could lead to off-by-one errors
        const arrayPattern = /\bchar\s+\w+\[(\d+)\];/g;
        while ((match = arrayPattern.exec(code)) !== null) {
        const bufferSize = parseInt(match[1], 10);
        if (bufferSize <= 10) { // Threshold can be adjusted
            issues.push(`Warning: Possible off-by-one error with buffer size ${bufferSize} at position ${match.index}. Ensure adequate space for null terminator.`);
        }
    }

    // Check for sprintf usage without bounds and snprintf exceeding buffer size
const sprintfPattern = /\b(sprintf|snprintf)\s*\(([^,]+),\s*(\d+)?\s*,\s*.+?\)/g;

while ((match = sprintfPattern.exec(code)) !== null) {
    const functionName = match[1];
    const bufferName = match[2];

    if (functionName === 'sprintf') {
        issues.push(
            `Warning: Use of sprintf detected with buffer ${bufferName}. Prefer snprintf for bounded writing.`
        );
    } else if (functionName === 'snprintf') {
        const specifiedBound = parseInt(match[3], 10);
        const bufferRegex = new RegExp(`\\bchar\\s+${bufferName}\\[(\\d+)\\];`);
        const bufferMatch = bufferRegex.exec(code);

        if (bufferMatch) {
            const bufferSize = parseInt(bufferMatch[1], 10);
            if (specifiedBound > bufferSize) {
                issues.push(
                    `Warning: snprintf usage with ${bufferName} exceeds buffer size. Reduce the size parameter.`
                );
            }
        }
    }
}

// Check for recursive functions with local buffers (stack overflow risk)
const recursivePattern = /\bvoid\s+(\w+)\s*\([^)]*\)\s*{[^}]*\bchar\s+(\w+)\[(\d+)\];[^}]*\b\1\s*\([^}]*\)/g;
while ((match = recursivePattern.exec(code)) !== null) {
    const funcName = match[1];
    issues.push(
        `Warning: Recursive function ${funcName} with local buffer detected. Ensure recursion depth is limited to prevent stack overflow.`
    );
}

// Check for functions with large local buffers (stack overflow risk in deeply nested calls)
const functionPattern = /\bvoid\s+(\w+)\s*\([^)]*\)\s*{[^}]*\bchar\s+(\w+)\[(\d+)\];/g;
const stackThreshold = 512; // Define a threshold for large buffer size
while ((match = functionPattern.exec(code)) !== null) {
    const funcName = match[1];
    const bufferSize = parseInt(match[3], 10);
    if (bufferSize > stackThreshold) {
        issues.push(
            `Warning: Function ${funcName} has a large local buffer (${bufferSize} bytes). Excessive nested calls may lead to stack overflow.`
        );
    }
}
// Check for variable-length arrays (VLAs)
const vlaPattern = /\bchar\s+\w+\[(\w+)\];/g;
while ((match = vlaPattern.exec(code)) !== null) {
    const sizeVariable = match[1];
    issues.push(
        `Warning: Variable-Length Array ${match[0]} detected. Use malloc/calloc for dynamic buffer allocation to prevent stack overflow.`
    );
}

// Check for unchecked return values of memory allocation functions
const allocationFunctions = ['malloc', 'calloc', 'realloc'];
allocationFunctions.forEach(func => {
    const regex = new RegExp(`\\b${func}\\b`);
    if (regex.test(code) && !new RegExp(`if\\s*\\(\\s*${func}`).test(code)) {
        issues.push(
            `Warning: Unchecked return value of ${func} detected. Ensure memory allocation success.`
        );
    }
});




    

    // Check for potential overflow in memcpy/memmove usage
    const memcopyPattern = /\b(memcpy|memmove)\s*\(([^,]+),\s*([^,]+),\s*(\d+)\)/g;
    while ((match = memcopyPattern.exec(code)) !== null) {
        const bufferName = match[2];
        const copySize = parseInt(match[3], 10);

        // Check the buffer size if it's declared in the code
        const bufferDeclarationRegex = new RegExp(`\\bchar\\s+${bufferName}\\[(\\d+)\\];`);
        const bufferMatch = bufferDeclarationRegex.exec(code);
        if (bufferMatch) {
            const bufferSize = parseInt(bufferMatch[1], 10);
            if (copySize > bufferSize) {
                issues.push(`Warning: Potential overflow in ${match[1]} usage with buffer ${bufferName}. Ensure copy size is within buffer bounds.`);
            }
        }
    }
    
    
    

    return issues;
}

// Race Condition Vulnerability Checks
function checkRaceConditionVulnerabilities(code: string): string[] {
    const issues: string[] = [];

    // Check for race condition in file access functions
    const racePattern = /\b(fopen|fwrite|fread|fclose)\b/;
    if (racePattern.test(code)) {
        issues.push("Warning: Improper file access detected. Ensure proper file locking to prevent race conditions.");
    }

    return issues;
}

// Other Vulnerability Checks
function checkOtherVulnerabilities(code: string): string[] {
    const issues: string[] = [];

    // Check for command injection
    const commandInjectionPattern = /system\(|popen\(|exec\(|fork\(|wait\(|systemp\(/;
    if (commandInjectionPattern.test(code)) {
        issues.push("Warning: Possible command injection vulnerability detected. Avoid using system calls with user input.");
    }

    // Check for path traversal
    const pathTraversalPattern = /\.\.\//;
    if (pathTraversalPattern.test(code)) {
        issues.push("Warning: Potential Path Traversal vulnerability detected. Avoid using relative paths with user input.");
    }

    // Check for hardcoded credentials
    const hardCodedPattern = /\b(password|secret|apikey)\s*=\s*["'].*["']/;
    if (hardCodedPattern.test(code)) {
        issues.push("Warning: Hardcoded credentials detected. Avoid hardcoding sensitive information.");
    }
    

    // Check for insecure random number generation
const randomPattern = /\b(rand|srand)\b/;
if (randomPattern.test(code)) {
    issues.push("Warning: Insecure random number generation detected. Consider using secure alternatives.");
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



// Heap Vulnerability Checks
function checkHeapOverflowVulnerabilities(code: string): string[] {
    const issues: string[] = [];
    return issues;
}


// Heap Vulnerability Checks
function analyzeCodeForPlaintextPasswords(code: string): string[] {
    const issues: string[] = [];

    // 1. Look for password-related variables
    const passwordPattern = /\b(pass|password|passwd| pwd | user_password | admin_password | auth_pass | login_password | secure_password | db_password | secret_key | passphrase |master_password)\b.*=/g;
    let match;
    while ((match = passwordPattern.exec(code)) !== null) {
        const passwordVar = match[0];
        issues.push(`Warning: Potential password variable (${passwordVar}) detected. Ensure it is not stored in plaintext.`);
    }
    //2.  Look for file write operations involving password variables
    const fileWritePattern = /\b(fwrite|fprintf|write|ofstream|fputs)\b\s*\(([^,]+),?/g;
    while ((match = fileWritePattern.exec(code)) !== null) {
        issues.push(`Warning: File write operation detected. Ensure sensitive data is encrypted before storage.`);
    }

    return issues;


}