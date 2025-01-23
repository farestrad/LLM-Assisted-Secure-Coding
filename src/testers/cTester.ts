import * as fs from 'fs';
import { exec } from 'child_process';
import * as vscode from 'vscode';
import { promisify } from 'util';

import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';

const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();


const execPromise = promisify(exec);

// Define the file path, with a fallback to `/tmp` if no workspace is open
const tempFilePath = vscode.workspace.workspaceFolders
    ? `${vscode.workspace.workspaceFolders[0].uri.fsPath}/temp_test_code.c`
    : `/tmp/temp_test_code.c`; // Fallback to a system temp directory

export async function runCTests(code: string, securityAnalysisProvider: any) {
    // Step 1: Run vulnerability checks
    const securityIssues = analyzeCodeForSecurityIssues(code);

    // Step 2: If vulnerabilities are found, fetch CVE details for them
    if (securityIssues.length > 0) {
        const cveDetails = await fetchCveDetailsForIssues(securityIssues);

        // Update the Security Analysis view with issues and CVEs
        securityAnalysisProvider.updateSecurityAnalysis(securityIssues);
        securityAnalysisProvider.updateCveDetails(cveDetails);
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

    } catch (error) {
        const err = error as Error; // Cast 'error' to 'Error' type
        console.error("Error in runCTests:", err.message);
        securityAnalysisProvider.updateSecurityAnalysis([`Error during testing: ${err.message}`]);
    }
}


// Helper function to fetch CVE details for detected vulnerabilities
async function fetchCveDetailsForIssues(issues: string[]): Promise<{ id: string; description: string }[]> {
    const cveDetails: { id: string; description: string }[] = [];

    for (const issue of issues) {
        try {
            // Query the CVE database for each issue
            const cves = await vulnerabilityDatabaseProvider.fetchMultipleCveDetails(issue);

            // Add relevant CVEs to the result list
            cves.forEach((cve: any) => {
                cveDetails.push({
                    id: cve.id,
                    description: cve.descriptions[0]?.value || 'No description available',
                });
            });
        } catch (error) {
            console.error(`Error fetching CVEs for "${issue}":`, error);
        }
    }

    return cveDetails;
}


/*
1- write ur name beside the tests that you want to work on (2 or 3)
2- create jira tickets for it 
3- research and do it by next week 
4- POSSIBLE IDEA : ADD HELPER METHODS SUCH AS CHECKKING INPUT SIZES HERE IF YOU THINK OTHERS CAN USE IT 
5- first come first serve.
*/

// who wants to work on deploying ? @lim
// Ask Fares if you need help to understand the code !

// Main analysis function
function analyzeCodeForSecurityIssues(code: string): string[] {
    const issues: string[] = [];
    
    // Perform different categories of checks
    issues.push(...checkBufferOverflowVulnerabilities(code));
    issues.push(...checkRaceConditionVulnerabilities(code));
    issues.push(...checkOtherVulnerabilities(code));
    issues.push(...checkHeapOverflowVulnerabilities(code));
    issues.push(...analyzeCodeForPlaintextPasswords(code));
    issues.push(...analyzeCodeForWeakHashingAndEncryption(code));
    issues.push(...checkInfiniteLoopsOrExcessiveResourceConsumption(code));
    issues.push(...checkIntegerOverflowUnderflow(code));
    issues.push(...checkRandomNumberGeneration(code));
    issues.push(...checkPathTraversalVulnerabilities(code));

    

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



        // Check for small buffer declarations that could lead to off-by-one errors (ABOUD)
        const arrayPattern = /\bchar\s+\w+\[(\d+)\];/g;
        while ((match = arrayPattern.exec(code)) !== null) {
        const bufferSize = parseInt(match[1], 10);
        if (bufferSize <= 10) { // Threshold can be adjusted
            issues.push(`Warning: Possible off-by-one error with buffer size ${bufferSize} at position ${match.index}. Ensure adequate space for null terminator.`);
        }
    }

    // Check for sprintf usage without bounds and snprintf exceeding buffer size (ABOUD)
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

// Check for recursive functions with local buffers (stack overflow risk) (ABOUD)
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

    // Check for hardcoded credentials
    const hardCodedPattern = /\b(password|secret|apikey)\s*=\s*["'].*["']/;
    if (hardCodedPattern.test(code)) {
        issues.push("Warning: Hardcoded credentials detected. Avoid hardcoding sensitive information.");
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



// Helper function to check if input is sanitized 
function isSanitized(input: string, code: string): boolean {
    const sanitizedPattern = new RegExp(`sanitize\\s*\\(\\s*${input}\\s*\\`, 'g');
    return sanitizedPattern.test(code);
}

// Check for insecure random number generation
function checkRandomNumberGeneration(code: string): string[] {
    const issues: string[] = [];
    let match;

    // Detect insecure random functions
    const insecureRandomPattern = /\b(rand|srand|random|drand48|lrand48|rand_r|random_r|srandom|srandom_r)\b/;
    if (insecureRandomPattern.test(code)) {
        issues.push("Warning: Insecure random number generator detected. Consider using secure alternatives or secure libraries.");
    }

    // Detect insecure seeding with time(NULL)
    const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;
    while ((match = randomSeedPattern.exec(code)) !== null) {
        issues.push("Warning: Using time(NULL) as a seed is insecure. Use a more secure seed source.");
    }

    // Detect use of insecure RNG in loops
    const loopPattern = /\b(rand|random|drand48|lrand48)\b.*?for\s*\(/g;
    while ((match = loopPattern.exec(code)) !== null) {
        issues.push(`Warning: Insecure RNG '${match[1]}' detected in a loop. Ensure unbiased and secure random number generation.`);
    }

    return issues;
}


function analyzeCodeForWeakHashingAndEncryption(code: string): string[] {
    const issues: string[] = [];

    // 1. Detect weak hashing mechanisms
    const weakHashPattern = /\b(md5|sha1|crypt)\b\s*\(/g;
    let match;
    while ((match = weakHashPattern.exec(code)) !== null) {
        const weakHash = match[1];
        issues.push(`Warning: Weak hashing algorithm (${weakHash}) detected. Consider using a strong hash function like bcrypt, scrypt, or Argon2.`);
    }

    // 2. Detect encryption usage for passwords
    const encryptionPattern = /\b(encrypt|aes_encrypt|des_encrypt|blowfish_encrypt|crypto_encrypt|rsa_encrypt)\b\s*\(/gi;
    while ((match = encryptionPattern.exec(code)) !== null) {
        const encryptionMethod = match[1];
        issues.push(`Warning: Passwords should not be encrypted using ${encryptionMethod}. Use a secure hashing algorithm (e.g., bcrypt, Argon2) instead.`);
    }

    // 3. Detect direct calls to insecure hash libraries in code
    const hashLibraryPattern = /\b#include\s*<openssl\/md5.h>|#include\s*<openssl\/sha.h>/g;
    if (hashLibraryPattern.test(code)) {
        issues.push(`Warning: Insecure hash library inclusion detected. Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.`);
    }

    return issues;
}

//for Denial of Service through infinite loops leading to a crash.
function checkInfiniteLoopsOrExcessiveResourceConsumption(code: string): string[] {
    const issues: string[] = [];
    let match;

    // Check for loops without clear termination
    const infiniteLoopPattern = /\bfor\s*\([^;]*;\s*;[^)]*\)|\bwhile\s*\(true\)/g;
    while ((match = infiniteLoopPattern.exec(code)) !== null) {
        issues.push(`Warning: Potential infinite loop detected at position ${match.index}. Ensure proper termination conditions.`);
    }

    // Detect excessive memory allocations
    const largeAllocationPattern = /\bmalloc\s*\(\s*(\d+)\s*\)|\bcalloc\s*\([^,]+,\s*(\d+)\)/g;
    while ((match = largeAllocationPattern.exec(code)) !== null) {
        const allocatedSize = parseInt(match[1] || match[2], 10);
        if (allocatedSize > 1024 * 1024) { // Example threshold: 1 MB
            issues.push(`Warning: Excessive memory allocation (${allocatedSize} bytes) detected. Review memory usage.`);
        }
    }

    return issues;
}

//testing for interger Overflow and Underflows
function checkIntegerOverflowUnderflow(code: string): string[] {
    const issues: string[] = [];
    const overflowPattern = /\b(\w+)\s*=\s*([\d\-]+)\s*([\+\-\*\/])\s*([\d\-]+)/g;
    const MAX_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1
    const MIN_INT = Number.MIN_SAFE_INTEGER; // -(2^53 - 1)

    let match;
    while ((match = overflowPattern.exec(code)) !== null) {
        const variable = match[1]; // Captured variable being assigned
        const leftOperand = parseInt(match[2], 10); // First number
        const operator = match[3]; // Arithmetic operator
        const rightOperand = parseInt(match[4], 10); // Second number

        // Perform the arithmetic operation
        let result;
        switch (operator) {
            case '+':
                result = leftOperand + rightOperand;
                break;
            case '-':
                result = leftOperand - rightOperand;
                break;
            case '*':
                result = leftOperand * rightOperand;
                break;
            case '/':
                result = rightOperand !== 0 ? leftOperand / rightOperand : null;
                break;
            default:
                result = null; // Should never hit this case with current regex
        }

        // Check for overflow/underflow
        if (result !== null && (result > MAX_INT || result < MIN_INT)) {
            issues.push(
                `Warning: Integer overflow/underflow detected for variable "${variable}" in operation "${leftOperand} ${operator} ${rightOperand}".`
            );
        }
    }

    return issues;
}


// Path Traversal Vulnerability Checks
function checkPathTraversalVulnerabilities(code: string): string[] {
    const issues: string[] = [];
    let match;

    // Check for path traversal patterns (e.g., "../") (Minhyeok)
    const pathTraversalPattern = /\.\.\//g;
    if (pathTraversalPattern.test(code)) {
        issues.push("Warning: Potential Path Traversal vulnerability detected. Avoid using relative paths with user input.");
    }

    // Check for risky functions that may lead to path traversal
    const riskyFunctions = ['fopen', 'readfile', 'writefile', 'unlink', 'rename'];
    riskyFunctions.forEach(func => {
        const regex = new RegExp(`\\b${func}\\b\\s*\\(([^)]+)\\)`, 'g');
        while ((match = regex.exec(code)) !== null) {
            const argument = match[1].trim();
            if (argument.includes('../') || argument.includes('"') || argument.includes('`')) {
                issues.push(`Warning: Path traversal vulnerability in ${func} with argument "${argument}". Avoid using relative paths with user input.`);
            }
        }
    });

    // Check for unsanitized input usage in file operations
    const usagePattern = /\b(open|read|write|fread|fwrite)\s*\(([^,]+),?/g;
    while ((match = usagePattern.exec(code)) !== null) {
        const input = match[2].trim();
        if (!isSanitized(input, code)) {
            issues.push(`Warning: Unsanitized input "${input}" detected in file operation. Ensure input is sanitized before use.`);
        }
    }

    return issues;
}
