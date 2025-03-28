import * as vscode from 'vscode';
import { SecurityCheck } from "../c/SecurityCheck";
// add struct
export class FileLevelSecurityCheck implements SecurityCheck {
    check(fileContent: string, fileName: string): string[] {
        const issues: string[] = [];

        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const weakIncludes = config.get<string[]>('weakHashIncludes', [
            'openssl/md5.h',
            'openssl/sha.h'
        ]);

        // Normalize line continuations (e.g., #include \
        const preprocessed = fileContent.replace(/\\\s*\n/g, '');

        weakIncludes.forEach(include => {
            const includePattern = new RegExp(`#include\\s*[<"]\\s*${include.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*[>"]`, 'gi');
            if (includePattern.test(preprocessed)) {
                issues.push(
                    `Warning: Insecure hash library inclusion detected in file "${fileName}". Avoid using ${include}.`
                );
            }
        });

        return issues;
    }
}
