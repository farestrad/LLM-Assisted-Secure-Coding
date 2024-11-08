import { runCTests } from './cTester';
import { runJavaTests } from './javaTester';

// Main testing function
export async function runTestsOnGeneratedCode(code: string, language: string, securityAnalysisProvider: any) {
    switch (language) {
        case 'c':
            await runCTests(code, securityAnalysisProvider);
            break;
        case 'java':
            await runJavaTests(code, securityAnalysisProvider);
            break;
        default:
            throw new Error(`Language ${language} not supported.`);
    }
}
