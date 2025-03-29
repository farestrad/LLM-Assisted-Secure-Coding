import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
import { CCodeParser } from '../parsers/cCodeParser';
import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
import { SecurityCheck } from "./c/SecurityCheck";
import { TOP_CWES, CVE_MAPPING } from '../SecurityAnalysisProvider';

// Dynamically import all security checks
import { BufferOverflowCheck } from "./c/checkBufferOverflowVulnerabilities";
//import { HeapOverflowCheck } from "./c/checkHeapOverflowVulnerabilities";
//import { PlaintextPasswordCheck } from "./c/analyzeCodeForPlaintextPasswords";
//import { RaceConditionCheck } from "./c/checkRaceConditionVulnerabilities";
//import { OtherVulnerabilitiesCheck } from "./c/checkOtherVulnerabilities";
//import { RandomNumberGenerationCheck } from "./c/checkRandomNumberGeneration";
//import { WeakHashingEncryptionCheck } from "./c/analyzeCodeForWeakHashingAndEncryption";
//import { InfiniteLoopCheck } from "./c/checkInfiniteLoopsOrExcessiveResourceConsumption";
//import { IntegerFlowCheck } from "./c/checkIntegerOverflowUnderflow";
//import { PathTraversalCheck } from "./c/checkPathTraversalVulnerabilities";
import { FileLevelSecurityCheck } from "./c/FileLevelSecurityCheck";




// Create an array of all security checks
const securityChecks: SecurityCheck[] = [
    new BufferOverflowCheck(),
    //new HeapOverflowCheck(),
    //new PlaintextPasswordCheck(),
    //new RaceConditionCheck(),
    //new OtherVulnerabilitiesCheck(),
    //new RandomNumberGenerationCheck(),
    //new WeakHashingEncryptionCheck(),
    //new InfiniteLoopCheck(),
   // new IntegerFlowCheck(),
    //new PathTraversalCheck(),
    new FileLevelSecurityCheck()
];

const execPromise = promisify(require('child_process').exec);
const vulnerabilityDatabaseProvider = new VulnerabilityDatabaseProvider();


// Create a mapping of security checks to their corresponding CWEs
const securityCheckToCWE: { [key: string]: number } = {
    'BufferOverflowCheck': 125,
    'HeapOverflowCheck': 125,
    'PlaintextPasswordCheck': 20,
    'RaceConditionCheck': 20,
    'OtherVulnerabilitiesCheck': 20,
    'RandomNumberGenerationCheck': 20,
    'WeakHashingEncryptionCheck': 20,
    'InfiniteLoopCheck': 400,
    'IntegerFlowCheck': 190,
    'PathTraversalCheck': 22,
};

// Create a mapping of security checks to their corresponding CVEs
export const securityCheckToCVE: { [key: string]: string[] } = {
    'BufferOverflowCheck': ["CVE-2021-1234"],
    'HeapOverflowCheck': ["CVE-2021-5678"],
    'PlaintextPasswordCheck': ["CVE-2021-9101"],
    'RaceConditionCheck': ["CVE-2021-1122"],
    'OtherVulnerabilitiesCheck': ["CVE-2021-3344"],
    'RandomNumberGenerationCheck': ["CVE-2021-5566"],
    'WeakHashingEncryptionCheck': ["CVE-2021-7788"],
    'InfiniteLoopCheck': ["CVE-2021-9900"],
    'IntegerFlowCheck': ["CVE-2021-1235"],
    'PathTraversalCheck': ["CVE-2021-6789"],
};

// Define the type for CWE
type CWE = {
    id: number;
    name: string;
    description: string;
};

/**
 * Main function to analyze C code for vulnerabilities.
 **/
export async function runCTests(code: string, securityAnalysisProvider: any) {
    try {
        // Step 1: Extract methods from the code
        const methods = CCodeParser.extractFunctions(code);


        // Step 2: Analyze each method for vulnerabilities
        const securityIssues: string[] = [];
        const foundCves: { id: string; description: string }[] = []; // Array to hold found CVEs

        methods.forEach((func) => {
            const issues = analyzeFunctionForSecurityIssues(func);
            securityIssues.push(...issues);
            
            // Collect CVEs for found issues only if issues are detected
            if (issues.length > 0) {
                issues.forEach(issue => {
                    const checkName = issue.split(' (')[0]; // Extract check name
                    
                    // Validate that the check name exists in the mapping
                    if (!(checkName in securityCheckToCVE)) {
                        console.warn(`Unexpected check name: ${checkName}`); // Log the unexpected check name
                        return; // Skip this issue
                    }

                    const cveIds = securityCheckToCVE[checkName]; // Fetch CVE IDs
                    
                    if (cveIds) {
                        cveIds.forEach(cveId => {
                            const cveDetail = CVE_MAPPING[cveId]; // Fetch CVE details
                            if (cveDetail) {
                                foundCves.push(...cveDetail);
                            } else {
                                console.error(`CVE detail not found for ID: ${cveId}`);
                            }
                        });
                    }
                });
            }
        });

        // Step 3: Update the security analysis provider with found issues and CVEs
        securityAnalysisProvider.updateSecurityAnalysis(securityIssues, foundCves);

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
        const checkName = check.constructor.name; // Get the name of the check class
        const cweId = securityCheckToCWE[checkName]; // Get the corresponding CWE ID

        // Check for vulnerabilities and add the CWE if applicable
        const foundIssues = check.check(func.functionBody, func.name);

        if (foundIssues.length > 0 && cweId) {
            foundIssues.forEach(issue => {
                const cwe: CWE | undefined = TOP_CWES.find(cwe => cwe.id === cweId);
                issues.push(`${issue} (CWE-${cweId}: ${cwe?.name})`);
            });
        } else {
            issues.push(...foundIssues);
        }
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

