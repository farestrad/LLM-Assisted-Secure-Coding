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
                return configValues[key]; // Return the appropriate config value based on the key
            })
        })
    }
}));

describe('OtherVulnerabilitiesCheck', () => {
  let otherVulnerabilitiesCheck: any;

  beforeEach(() => {
    otherVulnerabilitiesCheck = new OtherVulnerabilitiesCheck();
  });

  test('should detect command injection vulnerability', () => {
    const methodBody = `
      const command = "rm -rf " + userInput;
      system(command);
    `;
    const methodName = 'deleteFile';

    const issues = otherVulnerabilitiesCheck.check(methodBody, methodName);

    expect(issues).toContain(
      'Warning: Possible command injection vulnerability detected in method "deleteFile". Avoid using system calls with user input.'
    );
  });
});
