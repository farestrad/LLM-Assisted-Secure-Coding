import { HeapOverflowCheck } from '../testers/c/checkHeapOverflowVulnerabilities'; // Adjust the path accordingly

jest.mock('vscode', () => ({
    workspace: {
        getConfiguration: jest.fn().mockReturnValue({
            get: jest.fn().mockReturnValue(512)  // Mocking 'stackBufferThreshold' config value
        })
    }
}));

describe('HeapOverflowCheck', () => {
    let heapOverflowCheck: any;

    beforeEach(() => {
        heapOverflowCheck = new HeapOverflowCheck();
    });

    test('should return warning for unvalidated malloc allocation', () => {
        const methodBody = `char *buffer = malloc(size);`;
        const methodName = 'testFunction';
        const issues = heapOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: Untrusted allocation size for "buffer" (size) in "testFunction" at line 1');
    });
});
