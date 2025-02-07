import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { cCodeParser } from '../parsers/cCodeParser';
import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
import { SecurityCheck } from "./c/SecurityCheck";

// Dynamically import all security checks
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

// Create an array of all security checks
const securityChecks: SecurityCheck[] = [
    new BufferOverflowCheck(),
    new HeapOverflowCheck(),
    new PlaintextPasswordCheck(),
    new RaceConditionCheck(),
    new OtherVulnerabilitiesCheck(),
    new RandomNumberGenerationCheck(),
    new WeakHashingEncryptionCheck(),
    new InfiniteLoopCheck(),
    new IntegerFlowCheck(),
    new PathTraversalCheck(),
];

const execPromise = promisify(require('child_process').exec);
const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();

// // Define the file path, with a fallback to `/tmp` if no workspace is open
// const tempFilePath = vscode.workspace.workspaceFolders
//     ? `${vscode.workspace.workspaceFolders[0].uri.fsPath}/temp_test_code.c`
//     : `/tmp/temp_test_code.c`;

/**
 * Main function to analyze C code for vulnerabilities.
 **/
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

        // // Optional: Write test code to a file
        // fs.writeFileSync(tempFilePath, code);
        // console.log(`Test code written to ${tempFilePath}`);
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
 **/
function analyzeMethodForSecurityIssues(method: { name: string; parameters: string[]; body: string }): string[] {
    const issues: string[] = [];

    // Loop through all security checks dynamically
    securityChecks.forEach(check => {
        issues.push(...check.check(method.body, method.name));
    });

    return issues;
}

/**
 * Fetch CVE details for identified security issues.
 **/
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

