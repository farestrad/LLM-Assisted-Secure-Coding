import * as fs from 'fs';
import * as vscode from 'vscode';
import { promisify } from 'util';
//import { cCodeParser } from '../parsers/cCodeParser';
//import { VulnerabilityDatabaseProvider } from '../VulnerabilityDatabaseProvider';
//import { parseCCode } from '../parsers/cParser';

/**
 * Check for race condition vulnerabilities in a method. (Minhyeok)
 */
export class RaceConditionCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const fileAccessFunctions = new Set<string>();

    

    // Check for race condition in file access functions
    const config = vscode.workspace.getConfiguration('securityAnalysis');
    const raceCondtionKeywords = config.get<string[]>('raceConditionKeywords', ['fopen', 'freopen', 'fwrite', 'fread', 'fclose', 'fprintf', 'fputs', 'fscanf']);

    // Phase 1: Track File Access Functions
    const fileAccessPattern = new RegExp(`\\b(${raceCondtionKeywords.join('|')})\\s*\\(`, 'g'); 
    let match;

    while ((match = fileAccessPattern.exec(methodBody)) !== null) {
        const fileAccess = match[1];
        fileAccessFunctions.add(fileAccess);
        issues.push('Warning: File access function detected in method "${methodName}". Ensure proper file locking to prevent race condtions.');
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
    
    if (fileAccessFunctions.size > 0 && !hasFileLock) {
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
}
