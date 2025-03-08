import { runCTests } from './cTester';
import { runJavaTests } from './javaTester';
import { CCodeParser } from '../parsers/cCodeParser';

export async function runTestsOnGeneratedCode(code: string, language: string, securityAnalysisProvider: any) {
    switch (language) {
        case 'c':
            const extractedFunctions = CCodeParser.extractFunctions(code); // ✅ Extract functions first
            await runCTests(extractedFunctions, securityAnalysisProvider); // ✅ Pass structured function objects
            break;
        case 'java':
            await runJavaTests(code, securityAnalysisProvider);
            break;
        default:
            throw new Error(`Language ${language} not supported.`);
    }
}

