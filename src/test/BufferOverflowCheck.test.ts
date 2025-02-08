import { BufferOverflowCheck } from '../testers/c/checkBufferOverflowVulnerabilities'; // Adjust the path accordingly

jest.mock('vscode', () => ({
    workspace: {
        getConfiguration: jest.fn().mockReturnValue({
            get: jest.fn().mockReturnValue(512)  // Mocking 'stackBufferThreshold' config value
        })
    }
}));

describe('BufferOverflowCheck', () => {
    let bufferOverflowCheck: any;

    beforeEach(() => {
        bufferOverflowCheck = new BufferOverflowCheck();
    });

    test('should return warning for unsafe strcpy usage', () => {
        const methodBody = `char buffer[10]; strcpy(buffer, input);`;
        const methodName = 'testFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: Unvalidated strcpy usage with "buffer" in "testFunction"');
    });
});