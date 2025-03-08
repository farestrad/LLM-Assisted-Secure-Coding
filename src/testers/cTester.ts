import * as vscode from 'vscode';
import { promisify } from 'util';
import { CCodeParser } from '../parsers/cCodeParser';  // Use new Tree-sitter parser
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

/**
 * Main function to analyze C code for vulnerabilities.
 **/
export async function runCTests(
    extractedFunctions: {
        name: string;
        returnType: string;
        parameters: { type: string; name: string }[];
        lineNumber: number;
        functionBody: string;
        functionCalls: string[];
    }[], 
    securityAnalysisProvider: any
) {
    try {
        const securityIssues: string[] = [];

        // Iterate over structured function objects
        extractedFunctions.forEach((func) => {
            securityIssues.push(...analyzeFunctionForSecurityIssues(func));
        });

        // Fetch CVE details if vulnerabilities are found
        if (securityIssues.length > 0) {
            const cveDetails = await fetchCveDetailsForIssues(securityIssues);
            securityAnalysisProvider.updateCveDetails(cveDetails);
        }

        // Update security analysis results
        securityAnalysisProvider.updateSecurityAnalysis(securityIssues);
    } catch (error) {
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
 * Analyze a single function for security vulnerabilities.
 **/
function analyzeFunctionForSecurityIssues(func: {
    name: string;
    returnType: string;
    parameters: { type: string; name: string }[];
    lineNumber: number;
    functionBody: string;
    functionCalls: string[];
}): string[] {
    const issues: string[] = [];

    // Loop through all security checks dynamically
    securityChecks.forEach(check => {
        issues.push(...check.check(func.functionBody, func.name)); // Pass methodBody & methodName separately
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

