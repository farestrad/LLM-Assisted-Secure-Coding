import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { cCodeParser } from '../parsers/cCodeParser';
import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';

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
    const variables = new Map<string, number>();
    const validationChecks = new Set<string>();
    const calledFunctions = new Set<string>();
    const validationFunctions = new Set<string>();

    // Get configuration from VSCode
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const stackThreshold = config.get<number>('stackBufferThreshold', 512);

    // Phase 1: Enhanced Buffer Declaration Tracking
    const declRegex = /(\b(?:char|int|long|unsigned|signed|[\w_]+)\s+)+\s*(\w+)\s*\[\s*(\d+)\s*\]/g;
    let match;
    while ((match = declRegex.exec(methodBody)) !== null) {
        variables.set(match[2], parseInt(match[3], 10));
    }

    // Phase 2: Advanced Validation Check Detection
    const validationRegex = /(?:\b(?:if|while|for)\s*\(|&&|\|\|).*\b(?:strlen|sizeof|_countof)\s*\(\s*(\w+)\s*\).*?(?:\)|;)/g;
    while ((match = validationRegex.exec(methodBody)) !== null) {
        validationChecks.add(match[1]);
    }

    // Phase 3: Inter-procedural Validation Tracking
    const valFuncRegex = /(?:bool|int)\s+(\w+)\s*\(.*\b(const char\s*\*|void\s*\*).*\)/g;
    while ((match = valFuncRegex.exec(methodBody)) !== null) {
        validationFunctions.add(match[1]);
    }

    // Phase 4: Function Call Tracking
    const callRegex = /\b(\w+)\s*\(/g;
    while ((match = callRegex.exec(methodBody)) !== null) {
        calledFunctions.add(match[1]);
    }

    // Phase 5: Context-Aware Risky Function Analysis
    const functionChecks = [
        {
            pattern: /\b(strcpy|gets|sprintf)\s*\(\s*(\w+)\s*,/g,
            handler: (fn: string, buffer: string) => {
                if (!validationChecks.has(buffer) && !isValidatedByFunction(buffer)) {
                    return `Unvalidated ${fn} usage with "${buffer}"`;
                }
                return null;
            }
        },
        {
            pattern: /\bmalloc\s*\(\s*(\w+)\s*\)/g,
            handler: (_: string, sizeVar: string) => {
                if (!validationChecks.has(sizeVar)) {
                    return `Untrusted allocation size "${sizeVar}"`;
                }
                return null;
            }
        },
        {
            pattern: /\b(memcpy|memmove)\s*\(\s*(\w+)\s*,\s*\w+,\s*([^)]+)\s*\)/g,
            handler: (fn: string, destBuffer: string, sizeExpr: string) => {
                const declaredSize = variables.get(destBuffer);
                const sizeValue = parseSizeExpression(sizeExpr);
                
                if (declaredSize && sizeValue && sizeValue > declaredSize) {
                    return `${fn} copying ${sizeValue} bytes into "${destBuffer}" (${declaredSize} bytes)`;
                }
                return null;
            }
        }
    ];

    functionChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2], match[3]);
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });

    // Phase 6: Recursive Function Analysis
    if (calledFunctions.has(methodName)) {
        const localBuffers = Array.from(variables.keys()).join(', ');
        if (localBuffers) {
            issues.push(`Warning: Recursive function "${methodName}" with local buffers (${localBuffers})`);
        }
    }

    // Phase 7: Stack Allocation Analysis
    const largeBufferPattern = /\b(char|int|long)\s+(\w+)\s*\[\s*(\d+)\s*\]/g;
    while ((match = largeBufferPattern.exec(methodBody)) !== null) {
        const bufferSize = parseInt(match[3], 10);
        if (bufferSize > stackThreshold) {
            issues.push(`Warning: Large stack buffer "${match[2]}" (${bufferSize} bytes) in "${methodName}"`);
        }
    }

    // Phase 8: Pointer Arithmetic Checks
    const pointerRegex = /\b(\w+)\s*(\+|\-)=\s*\d+/g;
    while ((match = pointerRegex.exec(methodBody)) !== null) {
        if (variables.has(match[1])) {
            issues.push(`Warning: Pointer arithmetic on buffer "${match[1]}" in "${methodName}"`);
        }
    }

    // Phase 9: Array Index Validation
    const indexRegex = /\b(\w+)\s*\[\s*(\w+)\s*\]/g;
    while ((match = indexRegex.exec(methodBody)) !== null) {
        const [buffer, index] = [match[1], match[2]];
        if (!validationChecks.has(index)) {
            issues.push(`Warning: Unvalidated index "${index}" used with "${buffer}" in "${methodName}"`);
        }
    }

    // Phase 10: Memory Allocation Checks
    const allocationFunctions = ['malloc', 'calloc', 'realloc'];
    allocationFunctions.forEach((func) => {
        const allocationRegex = new RegExp(`\\b${func}\\s*\\(`, 'g');
        const checkedRegex = new RegExp(`if\\s*\\(\\s*${func}\\s*\\(`);

        while ((match = allocationRegex.exec(methodBody)) !== null) {
            if (!checkedRegex.test(methodBody)) {
                issues.push(`Warning: Unchecked return value of "${func}" in "${methodName}"`);
            }
        }
    });

    // Helper Functions
    function parseSizeExpression(expr: string): number | null {
        // Handle sizeof() expressions
        const sizeofMatch = expr.match(/sizeof\s*\(\s*(\w+)\s*\)/);
        if (sizeofMatch) return variables.get(sizeofMatch[1]) || null;

        // Handle arithmetic expressions
        if (expr.includes('+') || expr.includes('*')) {
            try {
                return eval(expr.replace(/\b(\w+)\b/g, (_, v) => variables.get(v)?.toString() || '0'));
            } catch {
                return null;
            }
        }

        // Handle numeric literals and variables
        return parseInt(expr, 10) || variables.get(expr) || null;
    }

    function isValidatedByFunction(buffer: string): boolean {
        return Array.from(validationFunctions).some(fn => 
            new RegExp(`\\b${fn}\\s*\\(\\s*${buffer}\\s*\\)`).test(methodBody)
        );
    }

    return issues;
}









////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////




/**
 * Check for heap overflow vulnerabilities in a method.
 */
function checkHeapOverflowVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const heapAllocations = new Map<string, { size: string, line: number }>();
    const validationChecks = new Set<string>();
    const arithmeticOperations = new Set<string>();
    const freedVariables = new Set<string>();
    let lineNumber = 1;

    // Phase 1: Track Heap Allocations and Reallocations
    const allocationRegex = /(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]+)\)/g;
    let match;
    while ((match = allocationRegex.exec(methodBody)) !== null) {
        const [varName, func, args] = [match[1], match[2], match[3]];
        const sizeExpr = func === 'calloc' ? args.split(',')[1] : args;

        heapAllocations.set(varName, {
            size: sizeExpr.trim(),
            line: lineNumber + countNewlines(methodBody.slice(0, match.index))
        });
    }

    // Phase 2: Detect Size Validation Patterns
    const validationRegex = /(?:if|while|assert)\s*\(.*\b(sizeof|strlen|_countof)\(([^)]+)\).*[<>=]/g;
    while ((match = validationRegex.exec(methodBody)) !== null) {
        validationChecks.add(match[2].trim());
    }

    // Phase 3: Analyze Size Calculations
    const arithmeticRegex = /(\w+)\s*=\s*(\w+)\s*([*+/-])\s*(\w+)/g;
    while ((match = arithmeticRegex.exec(methodBody)) !== null) {
        arithmeticOperations.add(match[1]);
        if (!validationChecks.has(match[2]) || !validationChecks.has(match[4])) {
            issues.push(`Warning: Unvalidated arithmetic operation (${match[0]}) in "${methodName}"`);
        }
    }

    // Phase 4: Analyze Memory Operations (Including Manual Buffer Copying)
    const memoryOperationChecks = [
        {
            pattern: /(memcpy|memmove|strcpy|strncpy|sprintf)\s*\(\s*(\w+)\s*,/g,
            handler: (fn: string, dest: string) => {
                const alloc = heapAllocations.get(dest);
                if (alloc && !isSizeValidated(alloc.size, validationChecks)) {
                    return `Unvalidated ${fn} to heap-allocated "${dest}"`;
                }
                return null;
            }
        },
        {
            pattern: /realloc\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\)/g,
            handler: (_: string, ptr: string, newSize: string) => {
                if (!isSizeValidated(newSize, validationChecks)) {
                    return `Unvalidated realloc of "${ptr}" with size "${newSize}"`;
                }
                return null;
            }
        },
        {
            pattern: /(\w+)\s*=\s*\w+\s*\+\s*\d+/g,
            handler: (varName: string) => {
                if (heapAllocations.has(varName) && !validationChecks.has(varName)) {
                    return `Unsafe pointer arithmetic on heap variable "${varName}"`;
                }
                return null;
            }
        }
    ];

    memoryOperationChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2], match[3] || '');
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });

    // Detect Manual Copying in Loops (Buffer Overflows)
    const loopCopyRegex = /\bfor\s*\(\s*[^;]+;\s*[^;]+;\s*[^)]+\s*\)\s*{[^}]*\b\w+\s*\[\s*\w+\s*\]\s*=/gs;
    while ((match = loopCopyRegex.exec(methodBody)) !== null) {
        issues.push(`Warning: Possible buffer overflow due to manual copying in loop in "${methodName}".`);
    }

    // Phase 5: Check Allocation Sizes
    heapAllocations.forEach((alloc, varName) => {
        if (!isSizeValidated(alloc.size, validationChecks)) {
            issues.push(`Warning: Untrusted allocation size for "${varName}" (${alloc.size}) in "${methodName}" at line ${alloc.line}`);
        }

        if (isPotentialIntegerOverflow(alloc.size, arithmeticOperations)) {
            issues.push(`Warning: Potential integer overflow in allocation size for "${varName}" (${alloc.size}) in "${methodName}"`);
        }
    });

    // Phase 6: Check Allocation Success (Improved)
    const uncheckedAllocRegex = /(\w+)\s*=\s*(malloc|calloc|realloc)\s*\([^)]+\)/g;
    while ((match = uncheckedAllocRegex.exec(methodBody)) !== null) {
        const varName = match[1];
        const func = match[2];

        // Look for an if-statement that checks if varName is NULL
        const validationPattern = new RegExp(`if\\s*\\(\\s*!?\\s*${varName}\\s*\\)`, 'g');
        if (!validationPattern.test(methodBody)) {
            issues.push(`Warning: Unchecked "${func}" result for "${varName}" in "${methodName}"`);
        }
    }

    // Phase 7: Detect Use-After-Free
    const freeRegex = /\bfree\s*\(\s*(\w+)\s*\)/g;
    while ((match = freeRegex.exec(methodBody)) !== null) {
        freedVariables.add(match[1]);
    }

    return issues;

    // Helper functions
    function countNewlines(str: string): number {
        return (str.match(/\n/g) || []).length;
    }

    function isSizeValidated(sizeExpr: string, validations: Set<string>): boolean {
        return sizeExpr.split(/\s*[+*/-]\s*/).some(part => 
            validations.has(part) || 
            /\d+/.test(part) || 
            part.startsWith('sizeof')
        );
    }

    function isPotentialIntegerOverflow(sizeExpr: string, arithmeticVars: Set<string>): boolean {
        return sizeExpr.split(/\s*[+*/-]\s*/).some(term => 
            arithmeticVars.has(term) || 
            (/\b\w+\b/.test(term) && !validationChecks.has(term))
        );
    }
}





//////


/**
 * Analyze a method for potential plaintext password vulnerabilities. (Minhyeok)
 */
function analyzeCodeForPlaintextPasswords(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const passwordVariables = new Set<string>();
    const fileWriteOperations = new Set<string>();

    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const passwordKeywords = config.get<string[]>('passwordkeywords', ['pass', 'password', 'passwd', 'pwd', 'user_password', 'admin_password', 
        'auth_pass', 'login_password', 'secure_password', 'db_password', 'secret_key', 'passphrase', 'master_password' ]);
    let match;

    // Phase 1: Password Variable Detection
    const passwordPattern = new RegExp(`\\b(${passwordKeywords.join('|')})\\b\\s*=\\s*["']?.+["']?`, 'gi');
    try {
        while ((match = passwordPattern.exec(methodBody)) !== null) {
            const passwordVar = match[0];
            passwordVariables.add(passwordVar);
            issues.push(`Warning: Potential password variable (${passwordVar}) detected in method "${methodName}". Ensure it is not stored in plaintext.`);
        }
    } catch (error) {
        console.error(`Error in password variable detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        passwordPattern.lastIndex = 0;
    }

    // Phase 2: File Write Operation Detection
    const fileWritePattern = /\b(fwrite|fprintf|write|ofstream|fputs)\s*\(\s*[^,]+/g;
    try {
        while ((match = fileWritePattern.exec(methodBody)) !== null) {
            const fileOp = match[1];
            const argument = match[2];
            fileWriteOperations.add(fileOp);
            if (isPasswordVariable(argument)) {
                issues.push(`Warning: Potential plaintext password written to file using "${fileOp} in method "${argument}". Ensure sensitive data is encrypted before storage.`);
            } else {
            issues.push(`Warning: File write operation detected in method "${methodName}". Ensure sensitive data is encrypted before storage.`);
            }
        }
    } catch (error) {
        console.error(`Error in file write operation detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        fileWritePattern.lastIndex = 0;
    }

    // Phase 3: Risky Password Checks
    const riskyPasswordChecks = [{
        pattern: /\b(printf|sprintf|fprintf|fwrite|fputs)\s*\(\s*(\w+)\s*,/g,
        handler: (fn: string, buffer: string) => {
            if (passwordVariables.has(buffer)) {
                return `Potential plaintext password passed to ${fn}`;
            }
            return null;
        }
    },
    {
        pattern: /\b(log|console\.log|System\.out\.println)\s*\(\s*([^]+)\s*\)/g,
        handler: (fn: string, arg: string) => {
            if (passwordVariables.has(arg)) {
                return `Potential plaintext password logged by ${fn}`;
            }
            return null;
        }
    }];

    riskyPasswordChecks.forEach(({ pattern, handler }) => {
        try {
            while ((match = pattern.exec(methodBody)) !== null) {
                const msg = handler(match[1], match[2]);
                if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
            }
        } catch (error) {
            console.error(`Error in risky password check: ${error}`);
        } finally {
            // Reset the lastIndex to avoid infinite loops
            pattern.lastIndex = 0;
        }
    });

    function isPasswordVariable(variable: string): boolean {
        return Array.from(passwordVariables).some((passwordVar) => new RegExp(`\\b${passwordVar}\\b`).test(variable));
    }
    // // Look for password-related variables
    // const passwordPattern = /\b(pass|password|passwd|pwd|user_password|admin_password|auth_pass|login_password|secure_password|db_password|secret_key|passphrase|master_password)\b\s*=\s*["']?.+["']?/gi;
    // while ((match = passwordPattern.exec(methodBody)) !== null) {
    //     const passwordVar = match[0];
    //     issues.push(
    //         `Warning: Potential password variable (${passwordVar}) detected in method "${methodName}". Ensure it is not stored in plaintext.`
    //     );
    // }

    // // Look for file write operations involving password variables
    // const fileWritePattern = /\b(fwrite|fprintf|write|ofstream|fputs)\s*\(\s*[^,]+/g;
    // while ((match = fileWritePattern.exec(methodBody)) !== null) {
    //     issues.push(
    //         `Warning: File write operation detected in method "${methodName}". Ensure sensitive data is encrypted before storage.`
    //     );
    // }

    return issues;
}
 




//////////





//////////




/**
 * Check for race condition vulnerabilities in a method. (Minhyeok)
 */
function checkRaceConditionVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const fileAccessFuctions = new Set<String>;

    // Check for race condition in file access functions
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const raceCondtionKeywords = config.get<string[]>('raceConditionKeywords', ['fopen', 'freopen', 'fwrite', 'fread', 'fclose', 'fprintf', 'fputs', 'fscanf']);
    let match;

    // Phase 1: Track File Access Functions
    const fileAccessPattern = new RegExp(`\\b(${raceCondtionKeywords.join('|')})\\s*\\(`, 'g'); 
    
    try{
        while ((match = fileAccessPattern.exec(methodBody)) !== null) {
            const fileAccess = match[1];
            fileAccessFuctions.add(fileAccess);
            issues.push('Warning: File access function detected in method "${methodName}". Ensure proper file locking to prevent race condtions.');
        }
    } catch (error) {
        console.error(`Error in file access function detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        fileAccessPattern.lastIndex = 0;
    }

    // Phase 2: Context-Aware Analysis
    const raceConditionChecks = [{
        pattern: /\b(fopen|freopen|fwrite|fread|fclose|fprintf|fputs|fscanf)\s*\(/g,
        handler: (fn: string) => { 
            return 'Warning: Potential race condition in low-level file operation "${fn}"';
        }
    },
    {
        pattern: /\b(access|stat|chmod|chown)\s*\(\s*[^,]+/g,
        handler: (fn: string) => {
            return 'Potential race condition in file metadata operation "${fn}"';
        }
    }];

    // Phase 3: File Locking Mechanism Detection
    const fileLockPattern = /\b(flock|lockf|fcntl)\s*\(/g;
    const hasFileLock = fileLockPattern.test(methodBody);
    
    if (fileAccessFuctions.size > 0 && !hasFileLock) {
        issues.push('Warning: File access detected without proper file locking in method "${methodName}". Ensure proper file locking to prevent issues.');
    }

    // // Check for race condition in file access functions
    // const racePattern = /\b(fopen|freopen|fwrite|fread|fclose|fprintf|fputs|fscanf)\s*\(/g;
    // if (racePattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Improper file access detected in method "${methodName}". Ensure proper file locking to prevent race conditions.`
    //     );
    // }
    
    return issues;
}




/////////




/**
 * Check for other vulnerabilities in a method. (Minhyeok)
 */
function checkOtherVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const vulnerabilities = new Map<string, Set<String>>(); // POTENTIAL FIX: Changed Set<String> to Set<string>


    // Get configuration from VSCode
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const commandInjectionFunctions = config.get<string[]>('commandInjectionFunctions', ['system', 'popen', 'exec', 'fork', 'wait', 'systemp']);
    const hardcodedCredentialsKeywords = config.get<string[]>('hardcodedCredentialsKeywords', ['password', 'secret', 'apikey', 'token', 'key']);
    const weakCryptoAlgorithms = config.get<string[]>('weakCryptoAlgorithms', ['MD5', 'SHA1']);
    const improperInputFunctions = config.get<string[]>('improperInputFunctions', ['atoi', 'atol', 'atof', 'gets', 'scanf']);
    const improperPrivilegeFunctions = config.get<string[]>('improperPrivilegeFunctions', ['setuid', 'setgid', 'seteuid', 'setegid']);
    const improperSessionFunctions = config.get<string[]>('improperSessionFunctions', ['session_start', 'session_id']);

    let match;

   // Check for command injection
   const commandInjectionPattern = new RegExp(`\\b(${commandInjectionFunctions.join('|')})\\b\\s*\\(`, 'g');
   commandInjectionPattern.lastIndex = 0; // FIX: Reset before use
   for (const match of methodBody.matchAll(commandInjectionPattern)) {
       const commandInjection = match[1];
       if (!vulnerabilities.has('commandInjection')) {
           vulnerabilities.set('commandInjection', new Set<string>());
       }
       vulnerabilities.get('commandInjection')?.add(commandInjection);
       issues.push(`Warning: Possible command injection vulnerability detected in method "${methodName}". Avoid using system calls with user input.`);
   }

    // Check for hardcoded credentials
    const hardCodedPattern = new RegExp(`\\b(${hardcodedCredentialsKeywords.join('|')})\\s*=\\s*["'].*["']`, 'gi');
    hardCodedPattern.lastIndex = 0; // FIX: Reset before use
    for (const match of methodBody.matchAll(hardCodedPattern)) {
        const credentials = match[0];
        if (!vulnerabilities.has('hardcodedCredentials')) {
            vulnerabilities.set('hardcodedCredentials', new Set<string>());
        }
        vulnerabilities.get('hardcodedCredentials')?.add(credentials);
        issues.push(`Warning: Hardcoded credentials detected in method "${methodName}". Avoid hardcoding sensitive information.`);
    }

     // Check for improper authentication handling
     const authPattern = /\b(==|!=)\s*["'].*["']/g;
     authPattern.lastIndex = 0; // FIX: Reset before use
     for (const match of methodBody.matchAll(authPattern)) {
         const comp = match[0];
         if (!vulnerabilities.has('improperAuthentication')) {
             vulnerabilities.set('improperAuthentication', new Set<string>());
         }
         vulnerabilities.get('improperAuthentication')?.add(comp);
         issues.push(`Warning: Improper authentication handling detected in method "${methodName}". Avoid using string comparison for sensitive data.`);
     }

    // Check for insecure cryptographic storage
    const cryptoPattern = new RegExp(`\\b(${weakCryptoAlgorithms.join('|')})\\b`, 'gi');
    cryptoPattern.lastIndex = 0; // FIX: Reset before use
    for (const match of methodBody.matchAll(cryptoPattern)) {
        const algorithm = match[0];
        if (!vulnerabilities.has('weakCryptoAlgorithms')) {
            vulnerabilities.set('weakCryptoAlgorithms', new Set<string>());
        }
        vulnerabilities.get('weakCryptoAlgorithms')?.add(algorithm);
        issues.push(`Warning: Insecure cryptographic storage detected in method "${methodName}". Avoid using weak hashing algorithms.`);
    }

    // Check for improper error handling and logging
    const errorPattern = /\b(printf|fprintf|stderr|strerror)\s*\(/g;
    errorPattern.lastIndex = 0; // FIX: Reset before use
    for (const match of methodBody.matchAll(errorPattern)) {
        if (!vulnerabilities.has('improperErrorHandling')) {
            vulnerabilities.set('improperErrorHandling', new Set<string>());
        }
        vulnerabilities.get('improperErrorHandling')?.add(match[0]);
        issues.push(`Warning: Improper error handling and logging detected in method "${methodName}". Ensure proper error messages and logging.`);
    }


    // Check for improper input validation
    const inputPattern = new RegExp(`\\b(${improperInputFunctions.join('|')})\\s*\\(`, 'g');
    inputPattern.lastIndex = 0; // FIX: Reset before use
    for (const match of methodBody.matchAll(inputPattern)) {
        const inputFunction = match[1];
        if (!vulnerabilities.has('improperInputValidation')) {
            vulnerabilities.set('improperInputValidation', new Set<string>());
        }
        vulnerabilities.get('improperInputValidation')?.add(inputFunction);
        issues.push(`Warning: Improper input validation detected in method "${methodName}". Ensure proper input validation and sanitization.`);
    }

    // Check for improper privilege management
    const privilegePattern = new RegExp(`\\b(${improperPrivilegeFunctions.join('|')})\\s*\\(`, 'g');
    privilegePattern.lastIndex = 0; // FIX: Reset before use
    for (const match of methodBody.matchAll(privilegePattern)) {
        const privilegeFunction = match[1];
        if (!vulnerabilities.has('improperPrivilegeManagement')) {
            vulnerabilities.set('improperPrivilegeManagement', new Set<string>());
        }
        vulnerabilities.get('improperPrivilegeManagement')?.add(privilegeFunction);
        issues.push(`Warning: Improper privilege management detected in method "${methodName}". Avoid using setuid, setgid, seteuid, and setegid.`);
    }

    // Check for improper session management
    const sessionPattern = new RegExp(`\\b(${improperSessionFunctions.join('|')})\\s*\\(`, 'g');
    sessionPattern.lastIndex = 0; // FIX: Reset before use
    for (const match of methodBody.matchAll(sessionPattern)) {
        const sessionFunction = match[1];
        if (!vulnerabilities.has('improperSessionManagement')) {
            vulnerabilities.set('improperSessionManagement', new Set<string>());
        }
        vulnerabilities.get('improperSessionManagement')?.add(sessionFunction);
        issues.push(`Warning: Improper session management detected in method "${methodName}". Ensure proper session handling.`);
    }

    return issues;
}

///////


/**
 * Helper function to check if input is sanitized in a method.
 */
// function isSanitized(input: string, methodBody: string): boolean {
//     const sanitizedPattern = new RegExp(`\\b(sanitize|validate|escape)\\s*\\(\\s*${input}\\s*\\)`, 'i');
//     return sanitizedPattern.test(methodBody);
// }



/**
 * Check for insecure random number generation in a method. (Minhyeok)
 */
function checkRandomNumberGeneration(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const insecureRandomFunctions = new Set<string>();
    const insecureSeeds = new Set<string>();
    const insecureLoops = new Set<string>();

    let match;

    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const secureRandomFunctions = config.get<string[]>('secureRandomFunctions', ['rand_s', 'rand_r', 'random_r', 'arc4random', 'getrandom', 'CryptGenRandom']);
    const secureSeeds = config.get<string[]>('secureSeeds', ['getrandom', 'CryptGenRandom']);
    const loopFunctions = config.get<string[]>('loopFunctions', ['rand', 'random', 'drand48', 'lrand48']);

    // Phase 1: Detect Insecure Random Functions
    const insecureRandomPattern = new RegExp(`\\b(${loopFunctions.join('|')})\\s*\\(`, 'g');
    try {
        while ((match = insecureRandomPattern.exec(methodBody)) !== null) {
            const func = match[1];
            insecureRandomFunctions.add(func);
            issues.push(`Warning: Insecure random number generator "${func}" detected in method "${methodName}". Use secure alternatives or libraries.`);
        }
    } catch (error) {
        console.error(`Error in insecure random function detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        insecureRandomPattern.lastIndex = 0;
    }
    

    // Phase 2: Detect Insecure Seeding with time(NULL)
    const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;
    while ((match = randomSeedPattern.exec(methodBody)) !== null) {
        insecureSeeds.add(match[0]);
        issues.push(`Warning: Using time(NULL) as a seed is insecure in method "${methodName}". Use a more secure seed source.`);
    }

    //Phase 3: Detect Insecure RNG in Loops
    const loopPattern = new RegExp(`\\b(${loopFunctions.join('|')})\\s*\\(`, 'g');
    try {
        while ((match = loopPattern.exec(methodBody)) !== null) {
            insecureLoops.add(match[0]);
            issues.push(`Warning: Insecure RNG "${match[0]}" detected in a loop in method "${methodName}". Ensure unbiased and secure random number generation.`);
        }
    }  catch (error) {
        console.error(`Error in insecure RNG detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        loopPattern.lastIndex = 0;
    }
    

    // Phase 4: Context-Aware Analysis
    const contextAnalysis = [
    {
        pattern: /\b(rand|random|drand48|lrand48)\b\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, args: string) => {
            if (!secureRandomFunctions.includes(fn)) {
                return `Insecure seed source "${args}" for ${fn}`;
            }
            return null;
        }
    },
    {
        pattern: /\b(srand|srand48|srandom)\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, seed: string) => {
            if (!secureSeeds.includes(seed)) {
                return `Insecure seed source "${seed}" for ${fn}`;
            }
                return null;
            }
    }];

    // Phase 5: Context Analysis
    contextAnalysis.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2]);
            if (msg) issues.push(`Warning: ${msg} in "${methodName}"`);
        }
    });
     
    // // Detect insecure random functions
    // const insecureRandomPattern = /\b(rand|srand|random|drand48|lrand48|rand_r|random_r|srandom|srandom_r)\b\s*\(/g;
    // if (insecureRandomPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Insecure random number generator detected in method "${methodName}". Consider using secure alternatives or libraries.`
    //     );
    // }

    // // Detect insecure seeding with time(NULL)
    // const randomSeedPattern = /\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)/g;

    // while ((match = randomSeedPattern.exec(methodBody)) !== null) {
    //     issues.push(
    //         `Warning: Using time(NULL) as a seed is insecure in method "${methodName}". Use a more secure seed source.`
    //     );
    // }

    // // Detect use of insecure RNG in loops
    // const loopPattern = /\b(rand|random|drand48|lrand48)\b.*?\bfor\s*\(/g;
    
    // while ((match = loopPattern.exec(methodBody)) !== null) {
    //     issues.push(
    //         `Warning: Insecure RNG '${match[1]}' detected in a loop in method "${methodName}". Ensure unbiased and secure random number generation.`
    //     );
    // }

    return issues;
}


//////////



/**
 * Analyze a method for weak hashing and encryption vulnerabilities. (Minhyeok)
 */
function analyzeCodeForWeakHashingAndEncryption(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const weakHashes = new Set<string>();
    const insecureEncryptionMethods = new Set<string>();
    const insecureHashLibraries = new Set<string>();
    let match;

    // Get configuration from VSCode
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const weakHashAlgorithms = config.get<string[]>('weakHashAlgorithms', ['md5', 'sha1', 'crypt']);
    const weakEncryptionMethods = config.get<string[]>('weakEncryptionMethods', ['encrypt', 'aes_encrypt', 'des_encrypt', 'blowfish_encrypt', 'crypto_encrypt', 'rsa_encrypt']);
    const insecureHashLibrariesList = config.get<string[]>('insecureHashLibraries', ['openssl/md5.h', 'openssl/sha.h']);

    // Detect weak hashing mechanisms
    const weakHashPattern = new RegExp(`\\b(${weakHashAlgorithms.join('|')})\\s*\\(`, 'gi');
    try{
        while ((match = weakHashPattern.exec(methodBody)) !== null) {
            const weakHash = match[1];
            weakHashes.add(weakHash);
            issues.push(`Warning: Weak hashing algorithm (${weakHash}) detected in method "${methodName}". Consider using a strong hash function like bcrypt, scrypt, or Argon2.`);
        }
    } catch (error) {
        console.error(`Error in weak hash detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        weakHashPattern.lastIndex = 0;
    }

    // Detect encryption usage for passwords
    const encryptionPattern = new RegExp(`\\b(${weakEncryptionMethods.join('|')})\\s*\\(`, 'gi');
    try {
        while ((match = encryptionPattern.exec(methodBody)) !== null) {
            const encryptionMethod = match[1];
            insecureEncryptionMethods.add(encryptionMethod);
            issues.push(
                `Warning: Passwords should not be encrypted using ${encryptionMethod} in method "${methodName}". Use a secure hashing algorithm (e.g., bcrypt, Argon2) instead.`
            );
        }
    } catch (error) {
        console.error(`Error in encryption detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        encryptionPattern.lastIndex = 0;
    }
    

    // Detect direct calls to insecure hash libraries in code
    const hashLibraryPattern = new RegExp(`\\b(${insecureHashLibrariesList.join('|')})\\b`, 'gi');
    if (hashLibraryPattern.test(methodBody)) {
        issues.push(
            `Warning: Insecure hash library inclusion detected in method "${methodName}". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.`
        );
    }

    return issues;
}



////////










/**
 * Check for infinite loops or excessive resource consumption in a method. (Minhyeok)
 */
function checkInfiniteLoopsOrExcessiveResourceConsumption(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const infiniteLoops = new Set<string>();
    const largeAllocations = new Set<string>();
    let match;

    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const infiniteLoopPatterns = config.get<string[]>('infiniteLoopPatterns', ['for\\s*\\([^;]*;\\s*;[^)]*\\)', 'while\\s*\\(\\s*(true|1)\\s*\\)']);
    const largeAllocationThreshold = config.get<number>('largeAllocationThreshold', 1024 * 1024); // Example threshold: 1 MB
    
    // Check for loops without clear termination
    const infiniteLoopPattern = new RegExp(`\\b(${infiniteLoopPatterns.join('|')})\\s*{`, 'gi');
    try {
        while ((match = infiniteLoopPattern.exec(methodBody)) !== null) {
            const loop = match[0];
            infiniteLoops.add(loop);
            issues.push(
                `Warning: Potential infinite loop detected in method "${methodName}" at position ${match.index}. Ensure proper termination conditions.`
            );
        }
    } catch (error) {
        console.error(`Error in infinite loop detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        infiniteLoopPattern.lastIndex = 0;
    }
    

    // Detect excessive memory allocations
    const largeAllocationPattern = new RegExp(`\\b(malloc|calloc|realloc)\\s*\\(\\s*(\\d+)\\s*\\)`, 'gi');
    try {
        while ((match = largeAllocationPattern.exec(methodBody)) !== null) {
            const allocatedSize = parseInt(match[1] || match[2], 10);
            if (allocatedSize > largeAllocationThreshold) { // Example threshold: 1 MB
                largeAllocations.add('${match[1]}(${match[2]})');
                issues.push(
                    `Warning: Excessive memory allocation (${allocatedSize} bytes) detected in method "${methodName}". Review memory usage.`
                );
            }
        }
    } catch (error) {
        console.error(`Error in large allocation detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        largeAllocationPattern.lastIndex = 0;
    }
    

    return issues;
}




//////////////



/**
 * Check for integer overflow and underflow vulnerabilities in a method. (Minhyeok)
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
 * Check for path traversal vulnerabilities in a method. (Minhyeok)
 */
function checkPathTraversalVulnerabilities(methodBody: string, methodName: string): string[] {
    const issues: string[] = [];
    const riskyPaths = new Set<string>();
    const riskyFunctionCalls = new Set<string>();
    const unsanitizedInputs = new Set<string>();
    let match;

    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const pathTraversalPatterns = config.get<string[]>('pathTraversalPatterns', ['../', '~/', '\\..\\']);
    const riskyFunctions = config.get<string[]>('riskyFunctions', ['fopen', 'readfile', 'writefile', 'unlink', 'rename']);
    const fileOperations = config.get<string[]>('fileOperations', ['open', 'read', 'write', 'fread', 'fwrite', 'unlink', 'rename']);

    // Phase 1: Path Traversal Pattern Detection
    const pathTraversalPattern = new RegExp(`\\b(${pathTraversalPatterns.join('|')})`, 'g');
    try {
        while ((match = pathTraversalPattern.exec(methodBody)) !== null) {
            const path = match[1];
            riskyPaths.add(path);
            issues.push(
                `Warning: Potential Path Traversal vulnerability detected in method "${methodName}". Avoid using relative paths with user input.`
            );
        }
    } catch (error) {
        console.error(`Error in path traversal detection: ${error}`);
    } finally {
        // Reset the lastIndex to avoid infinite loops
        pathTraversalPattern.lastIndex = 0;
    }
    
    
    // Phase 2: Risky Function Detection
    riskyFunctions.forEach((func: string) => {
        const funcPattern = new RegExp(`\\b${func}\\b\\s*\\(([^)]+)\\)`, 'g');
        try {
            while ((match = funcPattern.exec(methodBody)) !== null) {
                const argument = match[1].trim();
                riskyFunctionCalls.add(func);
                if (!isSanitized(argument, methodBody)) {
                    issues.push(
                        `Warning: Path traversal vulnerability detected in function "${func}" in method "${methodName}" with argument "${argument}". Avoid using relative paths with user input.`
                    );
                }
            }
        } catch (error) {
            console.error(`Error in risky function detection: ${error}`);
        } finally {
            // Reset the lastIndex to avoid infinite loops
            funcPattern.lastIndex = 0;
        }
        
    });

    // Phase 3: Unsanitized Input Detection
    const usagePattern = new RegExp(`\\b(${fileOperations.join('|')})\\s*\\(([^,]+),?`, 'g');
    try {
        while ((match = usagePattern.exec(methodBody)) !== null) {
            const input = match[2].trim();
            unsanitizedInputs.add(input);
            if (!isSanitized(input, methodBody)) {
                issues.push(
                    `Warning: Unsanitized input "${input}" detected in file operation in method "${methodName}". Ensure input is sanitized before use.`
                );
            }
        }
    } catch (error) {
        console.error(`Error in unsanitized input detection: ${error}`);
    } finally {
        usagePattern.lastIndex = 0;
    }
    

    // Phase 4: Context-Aware Analysis
    const contextChecks = [{
        pattern: /\b(exec|system|popen)\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, arg: string) => {
            if (!isSanitized(arg, methodBody) && (arg.includes('../') || arg.includes('"') || arg.includes('`'))) {
                return `Potential path traversal vulnerability detected in function "${fn}" with argument "${arg}" in method "${methodName}". Ensure input is sanitized before use.`;
            }
            return null;
        }
    },
    {
        pattern: /\b(include|require)\s*\(\s*([^)]+)\s*\)/g,
        handler: (fn: string, arg: string) => {
            if (!isSanitized(arg, methodBody) && (arg.includes('../') || arg.includes('"') || arg.includes('`'))) {
                return `Potential path traversal vulnerability detected in function "${fn}" with argument "${arg}" in method "${methodName}". Ensure input is sanitized before use.`;
            }
            return null;
        }
    }];

    contextChecks.forEach(({ pattern, handler }) => {
        while ((match = pattern.exec(methodBody)) !== null) {
            const msg = handler(match[1], match[2]);
            if (msg) issues.push(`Warning: ${msg}`);
        }
    });

    // Helper function to check if input is sanitized in a method.
    function isSanitized(input: string, methodBody: string): boolean {
        // Check if the input is sanitized using common sanitization functions
        const sanitizationPatterns = [
            /realpath\s*\(/,
            /basename\s*\(/,
            /dirname\s*\(/,
            /escapeshellarg\s*\(/,
            /escapeshellcmd\s*\(/,
            /htmlspecialchars\s*\(/,
            /htmlentities\s*\(/,
            /preg_replace\s*\(/
        ];
        return sanitizationPatterns.some(pattern => pattern.test(methodBody));
    }

    // Check for path traversal patterns (e.g., "../") 
    // const pathTraversalPattern = /\.\.\/|~\/|\\\.\.\\/g;
    // if (pathTraversalPattern.test(methodBody)) {
    //     issues.push(
    //         `Warning: Potential Path Traversal vulnerability detected in method "${methodName}". Avoid using relative paths with user input.`
    //     );
    // }

    // Check for risky functions that may lead to path traversal 
    // const riskyFunctions = ['fopen', 'readfile', 'writefile', 'unlink', 'rename'];
    // riskyFunctions.forEach((func) => {
    //     const regex = new RegExp(`\\b${func}\\b\\s*\\(([^)]+)\\)`, 'g');
    //     while ((match = regex.exec(methodBody)) !== null) {
    //         const argument = match[1].trim();
    //         if (argument.includes('../') || argument.includes('"') || argument.includes('`')) {
    //             issues.push(
    //                 `Warning: Path traversal vulnerability detected in function "${func}" in method "${methodName}" with argument "${argument}". Avoid using relative paths with user input.`
    //             );
    //         }
    //     }
    // });

    // Check for unsanitized input usage in file operations 
    // const usagePattern = /\b(open|read|write|fread|fwrite|unlink|rename)\s*\(([^,]+),?/g;
    
    // while ((match = usagePattern.exec(methodBody)) !== null) {
    //     const input = match[2].trim();
    //     if (!isSanitized(input, methodBody)) {
    //         issues.push(
    //             `Warning: Unsanitized input "${input}" detected in file operation in method "${methodName}". Ensure input is sanitized before use.`
    //         );
    //     }
    // }

    return issues;
}


/*
import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { cCodeParser } from '../parsers/cCodeParser';
import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';

// Import individual security checks
import { BufferOverflowCheck } from "./c/checkBufferOverflowVulnerabilities";
import { HeapOverflowCheck } from "./c/checkHeapOverflowVulnerabilities";
import { PlaintextPasswordCheck } from "./c/analyzeCodeForPlaintextPasswords";
import { RaceConditionCheck } from "./c/checkRaceConditionVulnerabilities";
import { OtherVulnerabilitiesCheck } from "./c/checkOtherVulnerabilities";
import { RandomNumberGenerationCheck } from "./c/checkRandomNumberGeneration";
import { WeakHashingEncryptionCheck } from "./c/analyzeCodeForWeakHashingAndEncryption";
import { InfiniteLoopCheck } from "./c/checkInfiniteLoopsOrExcessiveResourceConsumption";
import { IntegerFlowCheck } from "./c/checkIntegerOverflowUnderflow";
import { PathTraversalCheck } from "./c/checkPathTraversalVulnerabilities";

// Instantiate security check classes
const bufferOverflowCheck = new BufferOverflowCheck();
const heapOverflowCheck = new HeapOverflowCheck();
const plaintextPasswordCheck = new PlaintextPasswordCheck();
const raceConditionCheck = new RaceConditionCheck();
const otherVulnerabilitiesCheck = new OtherVulnerabilitiesCheck();
const randomNumberGenerationCheck = new RandomNumberGenerationCheck();
const weakHashingEncryptionCheck = new WeakHashingEncryptionCheck();
const infiniteLoopCheck = new InfiniteLoopCheck();
const integerOverflowCheck = new IntegerFlowCheck();
const pathTraversalCheck = new PathTraversalCheck();

const execPromise = promisify(require('child_process').exec);
const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();

// Define the file path, with a fallback to `/tmp` if no workspace is open
const tempFilePath = vscode.workspace.workspaceFolders
    ? `${vscode.workspace.workspaceFolders[0].uri.fsPath}/temp_test_code.c`
    : `/tmp/temp_test_code.c`;

/**
 * Main function to analyze C code for vulnerabilities.
 
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
 
function analyzeMethodForSecurityIssues(method: { name: string; parameters: string[]; body: string }): string[] {
    const issues: string[] = [];

    // Run each security check and collect issues
    issues.push(...bufferOverflowCheck.check(method.body, method.name)); // 3
    issues.push(...heapOverflowCheck.check(method.body, method.name)); // 4
    issues.push(...plaintextPasswordCheck.check(method.body, method.name)); // 1
    issues.push(...raceConditionCheck.check(method.body, method.name)); // 9
    issues.push(...otherVulnerabilitiesCheck.check(method.body, method.name)); // 7
    issues.push(...randomNumberGenerationCheck.check(method.body, method.name)); // 10
    issues.push(...weakHashingEncryptionCheck.check(method.body, method.name)); // 2
    issues.push(...infiniteLoopCheck.check(method.body, method.name)); // 5
    issues.push(...integerOverflowCheck.check(method.body, method.name)); // 6
    issues.push(...pathTraversalCheck.check(method.body, method.name)); // 8

    return issues;
}

/**
 * Fetch CVE details for identified security issues.
 
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
*/