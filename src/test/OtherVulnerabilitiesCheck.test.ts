import { OtherVulnerabilitiesCheck } from '../testers/c/checkOtherVulnerabilities'; // Adjust the path accordingly

jest.mock('vscode', () => ({
    workspace: {
        getConfiguration: jest.fn().mockReturnValue({
            get: jest.fn((key) => {
                const configValues: any = {
                    commandInjectionFunctions: ['system', 'popen', 'exec', 'fork', 'wait', 'systemp'],
                    hardcodedCredentialsKeywords: ['password', 'secret', 'apikey', 'token', 'key'],
                    weakCryptoAlgorithms: ['MD5', 'SHA1'],
                    improperInputFunctions: ['atoi', 'atol', 'atof', 'gets', 'scanf'],
                    improperPrivilegeFunctions: ['setuid', 'setgid', 'seteuid', 'setegid'],
                    improperSessionFunctions: ['session_start', 'session_id'],
                };
                return configValues[key];
            })
        })
    }
}));

describe('OtherVulnerabilitiesCheck', () => {
    let checker: any;

    beforeEach(() => {
        checker = new OtherVulnerabilitiesCheck();
    });

    test('detects command injection vulnerability', () => {
        const methodBody = 'system("rm -rf " + userInput);';
        const issues = checker.check(methodBody, 'deleteFile');
        expect(issues).toContainEqual(expect.stringContaining('command injection'));
    });

    test('detects hardcoded credentials', () => {
        const methodBody = 'const password = "12345";';
        const issues = checker.check(methodBody, 'login');
        expect(issues).toContainEqual(expect.stringContaining('Hardcoded credentials'));
    });

    test('detects improper authentication handling', () => {
        const methodBody = 'if (userInput == "admin") {';
        const issues = checker.check(methodBody, 'authCheck');
        expect(issues).toContainEqual(expect.stringContaining('Improper authentication handling'));
    });

    test('detects improper error handling and logging', () => {
      // A sample method body containing a call to fprintf(stderr, ...)
      const methodBody = 'if (error) { fprintf(stderr, "error occurred"); }';
      const methodName = 'errorLogger';
      
      const issues = checker.check(methodBody, methodName);
      
      // Expect that the issues array contains a warning message about improper error handling.
      expect(issues).toContainEqual(expect.stringContaining('Improper error handling and logging'));
    });

    test('detects weak cryptographic algorithms', () => {
        const methodBody = 'const hash = crypto.createHash("MD5").update(data).digest("hex");';
        const issues = checker.check(methodBody, 'hashData');
        expect(issues).toContainEqual(expect.stringContaining('Insecure cryptographic storage'));
    });

    test('detects improper input validation', () => {
        const methodBody = 'int num = atoi(userInput);';
        const issues = checker.check(methodBody, 'parseNumber');
        expect(issues).toContainEqual(expect.stringContaining('Improper input validation'));
    });

    test('detects improper privilege management', () => {
        const methodBody = 'setuid(0);';
        const issues = checker.check(methodBody, 'setPrivileges');
        expect(issues).toContainEqual(expect.stringContaining('Improper privilege management'));
    });

    test('detects improper session management', () => {
        const methodBody = 'session_start();';
        const issues = checker.check(methodBody, 'startSession');
        expect(issues).toContainEqual(expect.stringContaining('Improper session management'));
    });

    test('ignores safe code', () => {
        const methodBody = 'console.log("Hello, world!");';
        const issues = checker.check(methodBody, 'safeMethod');
        expect(issues).toHaveLength(0);
    });

    describe('Empty match branch coverage', () => {
        let originalExec = RegExp.prototype.exec;
        afterEach(() => RegExp.prototype.exec = originalExec);
      
        test('should break loops on empty match for all vulnerability patterns', () => {
          // Override exec to always return a fake match with an empty string.
          RegExp.prototype.exec = function(this: RegExp, input: string) {
            return { 0: "", index: 0, input } as RegExpExecArray;
          };
      
          const methodBody = `
            system('rm -rf /'); 
            const password = "secret"; 
            if(userInput == "admin") {} 
            fprintf(stderr, "error occurred"); 
            const hash = crypto.createHash("MD5"); 
            int num = atoi(userInput); 
            setuid(0); 
            session_start();
          `;
          const issues = checker.check(methodBody, "testMethod");
          // Expect no issues because each regex returns an empty match causing the loop to break.
          expect(issues).toEqual([]);
        });
      });
      
});
