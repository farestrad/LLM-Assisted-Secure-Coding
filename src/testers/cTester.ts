import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { cCodeParser } from '../parsers/cCodeParser';
import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';

const execPromise = promisify(require('child_process').exec);
const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();

// Define the file path, with a fallback to `/tmp` if no workspace is open
const tempFilePath = vscode.workspace.workspaceFolders
    ? `${vscode.workspace.workspaceFolders[0].uri.fsPath}/temp_test_code.c`
    : `/tmp/temp_test_code.c`;

/**
 * Main function to analyze C code for vulnerabilities.
 */
export async function runCTests(code: string, securityAnalysisProvider: any) {
    try {
        // Step 1: Extract methods from the code
        const methods = cCodeParser.extractMethods(code);

        // Step 2: Analyze each method for vulnerabilities
        const securityIssues: string[] = [];
        methods.forEach((method) => {
            securityIssues.push(...analyzeMethodForSecurityIssues(method));
        });

        // Step 3: Fetch CVE details if vulnerabilities are found
        if (securityIssues.length > 0) {
            const cveDetails = await fetchCveDetailsForIssues(securityIssues);
            securityAnalysisProvider.updateCveDetails(cveDetails);
        }

        // Step 4: Update the security analysis provider with found issues
        securityAnalysisProvider.updateSecurityAnalysis(securityIssues);

        // Optional: Write test code to a file
        fs.writeFileSync(tempFilePath, code);
        console.log(`Test code written to ${tempFilePath}`);
    } catch (error) {
        // Safely handle the error by checking its type
        if (error instanceof Error) {
            console.error('Error in runCTests:', error.message);
            securityAnalysisProvider.updateSecurityAnalysis([`Error during testing: ${error.message}`]);
        } else {
            console.error('Unexpected error in runCTests:', error);
            securityAnalysisProvider.updateSecurityAnalysis([`Unexpected error during testing: ${String(error)}`]);
        }
    }
}


/**
 * Analyze a single method for security vulnerabilities.
 */
function analyzeMethodForSecurityIssues(method: { name: string; parameters: string[]; body: string }): string[] {
    const issues: string[] = [];

    // Perform security checks on the method body
    issues.push(...checkBufferOverflowVulnerabilities(method.body, method.name));
    issues.push(...checkRaceConditionVulnerabilities(method.body, method.name));
    issues.push(...checkOtherVulnerabilities(method.body, method.name));
    issues.push(...checkHeapOverflowVulnerabilities(method.body, method.name));
    issues.push(...analyzeCodeForPlaintextPasswords(method.body, method.name));
    issues.push(...analyzeCodeForWeakHashingAndEncryption(method.body, method.name));
    issues.push(...checkInfiniteLoopsOrExcessiveResourceConsumption(method.body, method.name));
    issues.push(...checkIntegerOverflowUnderflow(method.body, method.name));
    issues.push(...checkRandomNumberGeneration(method.body, method.name));
    issues.push(...checkPathTraversalVulnerabilities(method.body, method.name));

    return issues;
}

/**
 * Fetch CVE details for identified security issues.
 */
async function fetchCveDetailsForIssues(issues: string[]): Promise<{ id: string; description: string }[]> {
    const cveDetails: { id: string; description: string }[] = [];

    for (const issue of issues) {
        try {
            const cves = await vulnerabilityDatabaseProvider.fetchMultipleCveDetails(issue);
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



/**
 * Check for buffer overflow vulnerabilities in a method.
 */
function checkBufferOverflowVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    let match;

    // Check for risky functions
    const riskyFunctions = ['strcpy', 'gets', 'sprintf'];
    riskyFunctions.forEach((func) => {
        const regex = new RegExp(`\\b${func}\\s*\\(.*\\)`, 'g');
        if (regex.test(methodBody)) {
            issues.push(
                `Warning: Use of ${func} detected in method "${methodName}". Consider using safer alternatives (e.g., strncpy, fgets, snprintf).`
            );
        }
    });

    // Check for buffer allocations without bounds checking
    const bufferRegex = /\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;/g;
    while ((match = bufferRegex.exec(methodBody)) !== null) {
        const bufferName = match[1];
        if (!new RegExp(`sizeof\\(${bufferName}\\)`).test(methodBody)) {
            issues.push(
                `Warning: Buffer "${bufferName}" in method "${methodName}" does not include bounds checking. Use sizeof(${bufferName}) to prevent overflow.`
            );
        }
    }

    // Check for malloc calls with insufficient size
    const mallocPattern = /\bmalloc\s*\(\s*(\d+|sizeof\s*\(\s*\w+\s*\))\s*\)/g;
    while ((match = mallocPattern.exec(methodBody)) !== null) {
        const allocatedSize = parseInt(match[1], 10);
        if (allocatedSize < 100) {
            issues.push(
                `Warning: Potentially insufficient memory allocation with malloc in method "${methodName}". Ensure buffer size is adequate.`
            );
        }
    }

    // Check for small buffer declarations that could lead to off-by-one errors
    const arrayPattern = /\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;/g;
    while ((match = arrayPattern.exec(methodBody)) !== null) {
        const bufferSize = parseInt(match[1], 10);
        if (bufferSize <= 10) {
            issues.push(
                `Warning: Possible off-by-one error with buffer size ${bufferSize} in method "${methodName}". Ensure adequate space for null terminator.`
            );
        }
    }

    // Check for sprintf usage without bounds and snprintf exceeding buffer size
    const sprintfPattern = /\b(sprintf|snprintf)\s*\(\s*([^,]+)\s*,\s*(\d+)?\s*,\s*.+?\)/g;
    while ((match = sprintfPattern.exec(methodBody)) !== null) {
        const functionName = match[1];
        const bufferName = match[2];

        if (functionName === 'sprintf') {
            issues.push(
                `Warning: Use of sprintf detected with buffer "${bufferName}" in method "${methodName}". Prefer snprintf for bounded writing.`
            );
        } else if (functionName === 'snprintf') {
            const specifiedBound = parseInt(match[3], 10);
            const bufferRegex = new RegExp(`\\bchar\\s+${bufferName}\\[(\\d+)\\];`);
            const bufferMatch = bufferRegex.exec(methodBody);

            if (bufferMatch) {
                const bufferSize = parseInt(bufferMatch[1], 10);
                if (specifiedBound > bufferSize) {
                    issues.push(
                        `Warning: snprintf usage with buffer "${bufferName}" in method "${methodName}" exceeds buffer size. Reduce the size parameter.`
                    );
                }
            }
        }
    }

    // Check for recursive functions with local buffers (stack overflow risk)
    const recursivePattern = /\bvoid\s+(\w+)\s*\([^)]*\)\s*{[^}]*?\bchar\s+(\w+)\s*\[\s*(\d+)\s*\];[^}]*?\b\1\s*\([^}]*?\)/gs;
    while ((match = recursivePattern.exec(methodBody)) !== null) {
        const funcName = match[1];
        issues.push(
            `Warning: Recursive function "${funcName}" with local buffer detected in method "${methodName}". Ensure recursion depth is limited to prevent stack overflow.`
        );
    }

    // Check for functions with large local buffers (stack overflow risk in deeply nested calls)
    const functionPattern = /\bvoid\s+(\w+)\s*\([^)]*\)\s*{[^}]*?\bchar\s+(\w+)\s*\[\s*(\d+)\s*\];/gs;
    const stackThreshold = 512; // Define a threshold for large buffer size
    while ((match = functionPattern.exec(methodBody)) !== null) {
        const funcName = match[1];
        const bufferSize = parseInt(match[3], 10);
        if (bufferSize > stackThreshold) {
            issues.push(
                `Warning: Function "${funcName}" in method "${methodName}" has a large local buffer (${bufferSize} bytes). Excessive nested calls may lead to stack overflow.`
            );
        }
    }

    // Check for variable-length arrays (VLAs)
    const vlaPattern = /\bchar\s+(\w+)\s*\[\s*(\w+)\s*\]\s*;/g;
    while ((match = vlaPattern.exec(methodBody)) !== null) {
        const sizeVariable = match[1];
        issues.push(
            `Warning: Variable-Length Array "${sizeVariable}" detected in method "${methodName}". Use malloc/calloc for dynamic buffer allocation to prevent stack overflow.`
        );
    }

    // Check for unchecked return values of memory allocation functions
    const allocationFunctions = ['malloc', 'calloc', 'realloc'];
    allocationFunctions.forEach((func) => {
        // Match allocation calls
        const allocationRegex = new RegExp(`\\b${func}\\s*\\(`, 'g');
        // Match `if` checks for the allocation
        const checkedRegex = new RegExp(`if\\s*\\(\\s*${func}\\s*\\(`);
    
        // Search for allocation calls
        let match;
        while ((match = allocationRegex.exec(methodBody)) !== null) {
            if (!checkedRegex.test(methodBody)) {
                issues.push(
                    `Warning: Unchecked return value of ${func} detected in method "${methodName}". Ensure memory allocation success.`
                );
            }
        }
    });
    

    // Check for potential overflow in memcpy/memmove usage
    const memcopyPattern = /\b(memcpy|memmove)\s*\(([^,]+),\s*([^,]+),\s*(\d+)\)/g;
    while ((match = memcopyPattern.exec(methodBody)) !== null) {
        const bufferName = match[2];
        const copySize = parseInt(match[3], 10);

        // Check the buffer size if it's declared in the code
        const bufferDeclarationRegex = new RegExp(`\\bchar\\s+${bufferName}\\[(\\d+)\\];`);
        const bufferMatch = bufferDeclarationRegex.exec(methodBody);
        if (bufferMatch) {
            const bufferSize = parseInt(bufferMatch[1], 10);
            if (copySize > bufferSize) {
                issues.push(
                    `Warning: Potential overflow in ${match[1]} usage with buffer "${bufferName}" in method "${methodName}". Ensure copy size is within buffer bounds.`
                );
            }
        }
    }

    return issues;
}




//////////




/**
 * Check for race condition vulnerabilities in a method.
 */
function checkRaceConditionVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];

    // Check for race condition in file access functions
    const racePattern = /\b(fopen|fwrite|fread|fclose)\b/;
    if (racePattern.test(methodBody)) {
        issues.push(
            `Warning: Improper file access detected in method "${methodName}". Ensure proper file locking to prevent race conditions.`
        );
    }

    return issues;
}




/////////




/**
 * Check for other vulnerabilities in a method.
 */
/**
 * Check for other vulnerabilities in a method.
 */
function checkOtherVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];

    // Check for command injection
    const commandInjectionPattern = /system\(|popen\(|exec\(|fork\(|wait\(|systemp\(/;
    if (commandInjectionPattern.test(methodBody)) {
        issues.push(
            `Warning: Possible command injection vulnerability detected in method "${methodName}". Avoid using system calls with user input.`
        );
    }

    // Check for hardcoded credentials
    const hardCodedPattern = /\b(password|secret|apikey)\s*=\s*["'].*["']/;
    if (hardCodedPattern.test(methodBody)) {
        issues.push(
            `Warning: Hardcoded credentials detected in method "${methodName}". Avoid hardcoding sensitive information.`
        );
    }

    // Check for improper authentication handling
    const authPattern = /\b(==|!=)\s*["'].*["']/;
    if (authPattern.test(methodBody)) {
        issues.push(
            `Warning: Improper authentication handling detected in method "${methodName}". Avoid using string comparison for sensitive data.`
        );
    }

    // Check for insecure cryptographic storage
    const cryptoPattern = /\bMD5\b|\bSHA1\b/;
    if (cryptoPattern.test(methodBody)) {
        issues.push(
            `Warning: Insecure cryptographic storage detected in method "${methodName}". Avoid using weak hashing algorithms.`
        );
    }

    // Check for improper error handling and logging
    const errorPattern = /\bprintf\(|fprintf\(|stderr|strerror\(/;
    if (errorPattern.test(methodBody)) {
        issues.push(
            `Warning: Improper error handling and logging detected in method "${methodName}". Ensure proper error messages and logging.`
        );
    }

    // Check for improper input validation
    const inputPattern = /\batoi\(|atol\(|atof\(|gets\(|scanf\(/;
    if (inputPattern.test(methodBody)) {
        issues.push(
            `Warning: Improper input validation detected in method "${methodName}". Ensure proper input validation and sanitization.`
        );
    }

    // Check for improper privilege management
    const privilegePattern = /\bsetuid\(|setgid\(|seteuid\(|setegid\(/;
    if (privilegePattern.test(methodBody)) {
        issues.push(
            `Warning: Improper privilege management detected in method "${methodName}". Avoid using setuid, setgid, seteuid, and setegid.`
        );
    }

    // Check for improper session management
    const sessionPattern = /\bsession_start\(|session_id\(/;
    if (sessionPattern.test(methodBody)) {
        issues.push(
            `Warning: Improper session management detected in method "${methodName}". Ensure proper session handling.`
        );
    }

    return issues;
}




///////////




/**
 * Check for heap overflow vulnerabilities in a method.
 */
function checkHeapOverflowVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];

    // Currently, there are no specific checks in the original function.
    // If any heap-specific checks are added later, implement them here.
    // For example:
    // - Detect unsafe dynamic memory allocations.
    // - Look for realloc patterns that lack proper error checking.

    return issues;
}




//////


/**
 * Analyze a method for potential plaintext password vulnerabilities.
 */
function analyzeCodeForPlaintextPasswords(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    let match;

    // Look for password-related variables
    const passwordPattern = /\b(pass|password|passwd|pwd|user_password|admin_password|auth_pass|login_password|secure_password|db_password|secret_key|passphrase|master_password)\b.*=/g;
    while ((match = passwordPattern.exec(methodBody)) !== null) {
        const passwordVar = match[0];
        issues.push(
            `Warning: Potential password variable (${passwordVar}) detected in method "${methodName}". Ensure it is not stored in plaintext.`
        );
    }

    // Look for file write operations involving password variables
    const fileWritePattern = /\b(fwrite|fprintf|write|ofstream|fputs)\b\s*\(([^,]+),?/g;
    while ((match = fileWritePattern.exec(methodBody)) !== null) {
        issues.push(
            `Warning: File write operation detected in method "${methodName}". Ensure sensitive data is encrypted before storage.`
        );
    }

    return issues;
}
 

///////


/**
 * Helper function to check if input is sanitized in a method.
 */
function isSanitized(input: string, methodBody: string): boolean {
    const sanitizedPattern = new RegExp(`sanitize\\s*\\(\\s*${input}\\s*\\)`, 'g');
    return sanitizedPattern.test(methodBody);
}



/**
 * Check for insecure random number generation in a method.
 */
function checkRandomNumberGeneration(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    let match;

    // Detect insecure random functions
    const insecureRandomPattern = /\b(rand|srand|random|drand48|lrand48|rand_r|random_r|srandom|srandom_r)\b/;
    if (insecureRandomPattern.test(methodBody)) {
        issues.push(
            `Warning: Insecure random number generator detected in method "${methodName}". Consider using secure alternatives or libraries.`
        );
    }

    // Detect insecure seeding with time(NULL)
    const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;
    while ((match = randomSeedPattern.exec(methodBody)) !== null) {
        issues.push(
            `Warning: Using time(NULL) as a seed is insecure in method "${methodName}". Use a more secure seed source.`
        );
    }

    // Detect use of insecure RNG in loops
    const loopPattern = /\b(rand|random|drand48|lrand48)\b.*?for\s*\(/g;
    while ((match = loopPattern.exec(methodBody)) !== null) {
        issues.push(
            `Warning: Insecure RNG '${match[1]}' detected in a loop in method "${methodName}". Ensure unbiased and secure random number generation.`
        );
    }

    return issues;
}


//////////



/**
 * Analyze a method for weak hashing and encryption vulnerabilities.
 */
function analyzeCodeForWeakHashingAndEncryption(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    let match;

    // Detect weak hashing mechanisms
    const weakHashPattern = /\b(md5|sha1|crypt)\b\s*\(/g;
    while ((match = weakHashPattern.exec(methodBody)) !== null) {
        const weakHash = match[1];
        issues.push(
            `Warning: Weak hashing algorithm (${weakHash}) detected in method "${methodName}". Consider using a strong hash function like bcrypt, scrypt, or Argon2.`
        );
    }

    // Detect encryption usage for passwords
    const encryptionPattern = /\b(encrypt|aes_encrypt|des_encrypt|blowfish_encrypt|crypto_encrypt|rsa_encrypt)\b\s*\(/gi;
    while ((match = encryptionPattern.exec(methodBody)) !== null) {
        const encryptionMethod = match[1];
        issues.push(
            `Warning: Passwords should not be encrypted using ${encryptionMethod} in method "${methodName}". Use a secure hashing algorithm (e.g., bcrypt, Argon2) instead.`
        );
    }

    // Detect direct calls to insecure hash libraries in code
    const hashLibraryPattern = /\b#include\s*<openssl\/md5.h>|#include\s*<openssl\/sha.h>/g;
    if (hashLibraryPattern.test(methodBody)) {
        issues.push(
            `Warning: Insecure hash library inclusion detected in method "${methodName}". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.`
        );
    }

    return issues;
}



////////



/**
 * Check for infinite loops or excessive resource consumption in a method.
 */
function checkInfiniteLoopsOrExcessiveResourceConsumption(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    let match;

    // Check for loops without clear termination
    const infiniteLoopPattern = /\bfor\s*\([^;]*;\s*;[^)]*\)|\bwhile\s*\(true\)/g;
    while ((match = infiniteLoopPattern.exec(methodBody)) !== null) {
        issues.push(
            `Warning: Potential infinite loop detected in method "${methodName}" at position ${match.index}. Ensure proper termination conditions.`
        );
    }

    // Detect excessive memory allocations
    const largeAllocationPattern = /\bmalloc\s*\(\s*(\d+)\s*\)|\bcalloc\s*\([^,]+,\s*(\d+)\)/g;
    while ((match = largeAllocationPattern.exec(methodBody)) !== null) {
        const allocatedSize = parseInt(match[1] || match[2], 10);
        if (allocatedSize > 1024 * 1024) { // Example threshold: 1 MB
            issues.push(
                `Warning: Excessive memory allocation (${allocatedSize} bytes) detected in method "${methodName}". Review memory usage.`
            );
        }
    }

    return issues;
}




//////////////



/**
 * Check for integer overflow and underflow vulnerabilities in a method.
 */
function checkIntegerOverflowUnderflow(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const overflowPattern = /\b(\w+)\s*=\s*([\d\-]+)\s*([\+\-\*\/])\s*([\d\-]+)/g;
    const MAX_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1
    const MIN_INT = Number.MIN_SAFE_INTEGER; // -(2^53 - 1)

    let match;
    while ((match = overflowPattern.exec(methodBody)) !== null) {
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
                `Warning: Integer overflow/underflow detected for variable "${variable}" in method "${methodName}". Operation: "${leftOperand} ${operator} ${rightOperand}".`
            );
        }
    }

    return issues;
}




//////////




/**
 * Check for path traversal vulnerabilities in a method.
 */
function checkPathTraversalVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    let match;

    // Check for path traversal patterns (e.g., "../")
    const pathTraversalPattern = /\.\.\//g;
    if (pathTraversalPattern.test(methodBody)) {
        issues.push(
            `Warning: Potential Path Traversal vulnerability detected in method "${methodName}". Avoid using relative paths with user input.`
        );
    }

    // Check for risky functions that may lead to path traversal
    const riskyFunctions = ['fopen', 'readfile', 'writefile', 'unlink', 'rename'];
    riskyFunctions.forEach((func) => {
        const regex = new RegExp(`\\b${func}\\b\\s*\\(([^)]+)\\)`, 'g');
        while ((match = regex.exec(methodBody)) !== null) {
            const argument = match[1].trim();
            if (argument.includes('../') || argument.includes('"') || argument.includes('`')) {
                issues.push(
                    `Warning: Path traversal vulnerability detected in function "${func}" in method "${methodName}" with argument "${argument}". Avoid using relative paths with user input.`
                );
            }
        }
    });

    // Check for unsanitized input usage in file operations
    const usagePattern = /\b(open|read|write|fread|fwrite)\s*\(([^,]+),?/g;
    while ((match = usagePattern.exec(methodBody)) !== null) {
        const input = match[2].trim();
        if (!isSanitized(input, methodBody)) {
            issues.push(
                `Warning: Unsanitized input "${input}" detected in file operation in method "${methodName}". Ensure input is sanitized before use.`
            );
        }
    }

    return issues;
}

