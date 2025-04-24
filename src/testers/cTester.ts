import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { CCodeParser } from '../parsers/cCodeParser';
import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
import { SecurityCheck } from "./c/SecurityCheck";
//import { TOP_CWES } from '../SecurityAnalysisProvider';

// Import the improved CWE mappings
import { 
    CWE, 
    CWE_DATABASE, 
    securityCheckToCWE, 
    CVE_MAPPING, 
    getCWEsForSecurityCheck 
} from '../SecurityAnalysisProvider';

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
import { FloatingInMemoryCheck } from "./c/FloatingInMemoryCheck";
// import { FileLevelSecurityCheck } from "./c/FileLevelSecurityCheck";

// Create an array of all security checks
const securityChecks: SecurityCheck[] = [
    new BufferOverflowCheck(),
    new FloatingInMemoryCheck(),
    new HeapOverflowCheck(),
    new PlaintextPasswordCheck(),
    new RaceConditionCheck(),
    new OtherVulnerabilitiesCheck(),
    new RandomNumberGenerationCheck(),
    new WeakHashingEncryptionCheck(),
    new InfiniteLoopCheck(),
    new IntegerFlowCheck(),
    new PathTraversalCheck(),
    // new FileLevelSecurityCheck()
];

const execPromise = promisify(require('child_process').exec);
const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();

/**
 * Main function to analyze C code for vulnerabilities.
 **/
export async function runCTests(code: string, securityAnalysisProvider: any) {
    try {
        // Step 1: Extract methods from the code
        const methods = CCodeParser.extractFunctions(code);

        // Step 2: Analyze each method for vulnerabilities
        const securityIssues: string[] = [];
        const foundCves: { id: string; description: string }[] = []; 
        const matchedCWEs = new Set<CWE>(); // Store matched CWEs without duplicates

        methods.forEach((func) => {
            const { issues, cweIds } = analyzeFunctionForSecurityIssues(func);
            securityIssues.push(...issues);

            // Collect CWE details for matched CWE IDs
            cweIds.forEach(cweId => {
                const cwe = CWE_DATABASE[cweId];
                if (cwe) {
                    matchedCWEs.add(cwe);
                }
            });

            // Collect CVEs for found issues organized by check name
            if (issues.length > 0) {
                // Track which check types have been found to avoid duplicate CVEs
                const foundCheckTypes = new Set<string>();
                
                issues.forEach(issue => {
                    // Extract the check name from the issue message if possible
                    const checkName = extractCheckNameFromIssue(issue);
                    
                    if (checkName && !foundCheckTypes.has(checkName)) {
                        foundCheckTypes.add(checkName);
                        
                        const cvesForCheck = CVE_MAPPING[checkName];
                        if (cvesForCheck) {
                            foundCves.push(...cvesForCheck);
                        }
                    }
                });
            }
        });

        // Step 3: Update the security analysis provider with found issues, CWEs, and CVEs
        securityAnalysisProvider.updateSecurityAnalysis(
            securityIssues, 
            foundCves, 
            Array.from(matchedCWEs)
        );

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
 * Helper function to extract the check name from an issue message
 */
function extractCheckNameFromIssue(issue: string): string | null {
    // Implement a more robust way to identify which check generated the issue
    // This is a simplified approach - you may want to implement a more structured
    // approach where each check reports its class name with the issues
    
    // Some checks have distinctive prefixes or keywords
    if (issue.includes("buffer overflow") || issue.includes("Buffer overflow")) {
        return "BufferOverflowCheck";
    } else if (issue.includes("heap overflow") || issue.includes("Heap overflow")) {
        return "HeapOverflowCheck";
    } else if (issue.includes("password") || issue.includes("credential")) {
        return "PlaintextPasswordCheck";
    } else if (issue.includes("race condition") || issue.includes("TOCTOU")) {
        return "RaceConditionCheck";
    } else if (issue.includes("command injection") || issue.includes("SQL injection")) {
        return "OtherVulnerabilitiesCheck";
    } else if (issue.includes("random") || issue.includes("RNG")) {
        return "RandomNumberGenerationCheck";
    } else if (issue.includes("hash") || issue.includes("encryption") || issue.includes("crypto")) {
        return "WeakHashingEncryptionCheck";
    } else if (issue.includes("infinite loop") || issue.includes("resource consumption")) {
        return "InfiniteLoopCheck";
    } else if (issue.includes("integer overflow") || issue.includes("integer underflow")) {
        return "IntegerFlowCheck";
    } else if (issue.includes("path traversal") || issue.includes("directory traversal")) {
        return "PathTraversalCheck";
    } else if (issue.includes("use after free") || issue.includes("double free") || issue.includes("NULL pointer")) {
        return "FloatingInMemoryCheck";
    }
    
    // If no match, return null
    return null;
}

/**
 * Analyze a single method for security vulnerabilities.
 **/
function analyzeFunctionForSecurityIssues(func: {
    name: string;
    returnType: string;
    parameters: { type: string; name: string }[];
    lineNumber: number;
    functionBody: string;
    functionCalls: string[];
}): { issues: string[], cweIds: number[] } {
    const issues: string[] = [];
    const cweIds: Set<number> = new Set<number>(); // Use a Set to avoid duplicates

    securityChecks.forEach(check => {
        const checkName = check.constructor.name;
        const cweIdsForCheck = securityCheckToCWE[checkName] || [];
        const foundIssues = check.check(func.functionBody, func.name);

        if (foundIssues.length > 0) {
            // Annotate issues with check name for better tracking
            const annotatedIssues = foundIssues.map(issue => `${issue} (${checkName})`);
            issues.push(...annotatedIssues);

            // Add all CWE IDs for this check to our set
            cweIdsForCheck.forEach(id => cweIds.add(id));
        }
    });

    return { issues, cweIds: Array.from(cweIds) };
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

/**
 * Helper function to get a human-readable summary of identified CWEs
 */
export function getCWESummary(cweIds: number[]): string {
    const summaries = cweIds.map(id => {
        const cwe = CWE_DATABASE[id];
        return cwe ? `CWE-${cwe.id}: ${cwe.name}` : `Unknown CWE-${id}`;
    });
    
    return summaries.join('\n');
}