import { PlaintextPasswordCheck } from '../testers/c/analyzeCodeForPlaintextPasswords';

jest.mock('vscode', () => ({
    workspace: {
        getConfiguration: jest.fn(() => ({
            get: jest.fn(() => ['pass', 'password', 'pwd', 'secret_key', 'auth_pass'])
        }))
    }
}));

describe('PlaintextPasswordCheck Unit Tests', () => {
    let checker: any;
    let passwordVariables: any;

    beforeEach(() => {
        checker = new PlaintextPasswordCheck();
        passwordVariables = new Set(['password', 'userPass', 'pwd']);
    });

    test('Detects plaintext password assignment', () => {
        const methodBody = `char *password = "mysecret";`;
        const methodName = "testFunction";
        const issues = checker.check(methodBody, methodName);
        
        expect(issues).toEqual([
            expect.stringContaining('Potential password variable')
        ]);
    });

    test('Detects file write operations involving passwords', () => {
        const methodBody = `fprintf(file, "Password: %s", password);`;
        const methodName = "testFunction";
        const issues = checker.check(methodBody, methodName);
        
        expect(issues).toEqual([
            expect.stringContaining('File write operation detected')
        ]);
    });


    test('Detects use of secret key variable', () => {
        const methodBody = `const char* secret_key = "123456";`;
        const methodName = "testFunction";
        const issues = checker.check(methodBody, methodName);
        
        expect(issues).toEqual([
            expect.stringContaining('Potential password variable')
        ]);
    });

    test('Ignores unrelated code', () => {
        const methodBody = `int value = 42; printf("Value: %d", value);`;
        const methodName = "testFunction";
        const issues = checker.check(methodBody, methodName);
        
        expect(issues).toEqual([]);
    });

    test('Detects risky plaintext password usage in function calls', () => {
        const methodBody = `
            char *password = "mysecret";
            // This should trigger the "passed" check since the first argument is 'password'
            printf(password, "format string");
            // This should trigger the "logged" check
            console.log(password);
        `;
        const methodName = "testFunction";
        const issues = checker.check(methodBody, methodName);
        
        expect(issues).toEqual(expect.arrayContaining([
             expect.stringContaining('Potential plaintext password passed to printf'),
             expect.stringContaining('Potential plaintext password logged by console.log')
        ]));
    });
    
    test('Risky checks return null for non-password variable usage', () => {
        const methodBody = `
            int notAPassword = 1234;
            // Although these functions match the risky call regex, "notAPassword" is not detected as a password variable.
            printf(notAPassword, "format string");
            console.log(notAPassword);
        `;
        const methodName = "testFunction";
        const issues = checker.check(methodBody, methodName);
        // Expect no warnings from risky checks since notAPassword isn't in the password variable set.
        expect(issues).toEqual([]);
    });
    
});
