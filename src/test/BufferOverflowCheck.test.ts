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
    let checker: BufferOverflowCheck;

    beforeEach(() => {
    checker = new BufferOverflowCheck();
    });


    test('should return warning for unsafe strcpy usage', () => {
        const methodBody = `char buffer[10]; strcpy(buffer, input);`;
        const methodName = 'testFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: Unvalidated strcpy usage with "buffer" in "testFunction"');
    });

    test('should return warning for unsafe memcpy usage', () => {
        const methodBody = `char buffer[10]; memcpy(buffer, input, 20);`;
        const methodName = 'testMemcpyFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: memcpy copying 20 bytes into "buffer" (10 bytes) in "testMemcpyFunction"');
    });

    test('should detect unvalidated index usage', () => {
        const methodBody = `char buffer[10]; buffer[index] = 'A';`;
        const methodName = 'testIndexFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: Unvalidated index "index" used with "buffer" in "testIndexFunction"');
    });

    test('should return warning for large stack buffer allocation', () => {
        const methodBody = `char largeBuffer[1024];`;
        const methodName = 'testLargeBufferFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: Large stack buffer "largeBuffer" (1024 bytes) in "testLargeBufferFunction"');
    });

    test('should detect unchecked memory allocation', () => {
        const methodBody = `char *ptr = malloc(256);`;
        const methodName = 'testMallocFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toContain('Warning: Unchecked return value of "malloc" in "testMallocFunction"');
    });

    test('should detect recursive function that modifies buffer unsafely', () => {
        const methodBody = `
            void recurse(char buffer[20], int index) { 
                buffer[index] = 'A'; 
                recurse(buffer, index + 1); 
            }`;
        const methodName = 'testRecursiveFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toContain('Warning: Recursive function "testRecursiveFunction" with local buffers (buffer)');
        expect(issues).toContain('Warning: Unvalidated index "index" used with "buffer" in "testRecursiveFunction"');
    });
    

    test('should not flag safe buffer usage', () => {
        const methodBody = `char buffer[10]; if (strlen(input) < sizeof(buffer)) { strcpy(buffer, input); }`;
        const methodName = 'safeFunction';
        const issues = bufferOverflowCheck.check(methodBody, methodName);

        expect(issues).toEqual([]);
    });

    test('should handle multiple validation checks before strcpy', () => {
        const methodBody = `
            char buffer[10]; 
            if (strlen(input) < sizeof(buffer) && isSafe(input)) {
                strcpy(buffer, input);
            }`;
        const methodName = 'testMultiValidation';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toEqual([]); // No warning should be triggered
    });

    test('should detect validation through variable assignment', () => {
        const methodBody = `
            char buffer[10];
            int safeSize = sizeof(buffer);
            if (strlen(input) < safeSize) {
                strcpy(buffer, input);
            }`;
        const methodName = 'testVarValidation';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toEqual([]); // No warning should be triggered
    });
    
    test('should detect dynamic allocation with unvalidated size', () => {
        const methodBody = `
            int size;
            scanf("%d", &size);
            char *buffer = malloc(size);
            strcpy(buffer, input);`;
        const methodName = 'testUnvalidatedMalloc';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toContain('Warning: Untrusted allocation size "size" in "testUnvalidatedMalloc"');
    });
    
    test('should not flag strcpy when buffer is validated in another function', () => {
        const methodBody = `
            bool validate(const char* input) { return strlen(input) < 10; }
            char buffer[10];
            if (validate(input)) {
                strcpy(buffer, input);
            }`;
        const methodName = 'testFunctionValidation';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toEqual([]); // No warning should be triggered
    });
    
    test('should track function-based validation correctly', () => {
        const methodBody = `
            bool isValid(const char* input) { return strlen(input) < 10; }
            char buffer[10];
            if (isValid(input)) {
                strcpy(buffer, input);
            }`;
        const issues = bufferOverflowCheck.check(methodBody, 'testFunctionValidation');
    
        expect(issues).toEqual([]); // No warning should be triggered
    });
    
    test('should detect indirect size overflow in memcpy', () => {
        const methodBody = `
            int bufferSize = 10;
            char buffer[10];
            memcpy(buffer, input, bufferSize + 5);`;
        const issues = bufferOverflowCheck.check(methodBody, 'testMemcpyIndirect');
    
        expect(issues).toContain('Warning: memcpy copying 15 bytes into "buffer" (10 bytes) in "testMemcpyIndirect"');
    });
    
    test('should detect recursive function call with buffer usage', () => {
        const methodBody = `
            void recursiveFunction(char buffer[20]) { 
                buffer[0] = 'A'; 
                recursiveFunction(buffer); 
            }`;
        const issues = bufferOverflowCheck.check(methodBody, 'recursiveFunction');
    
        expect(issues).toContain('Warning: Recursive function "recursiveFunction" with local buffers (buffer)');
    });
    

    test('should detect pointer arithmetic on buffer', () => {
        const methodBody = `
            char buffer[10];
            char *ptr = buffer;
            ptr += 2;`;
        const issues = bufferOverflowCheck.check(methodBody, 'testPointerArithmetic');
    
        expect(issues).toContain('Warning: Pointer arithmetic on buffer "ptr" in "testPointerArithmetic"');
    });
    
    test('should detect unchecked malloc return value', () => {
        const methodBody = `
            char *buffer = malloc(256);
            strcpy(buffer, input);`;
        const issues = bufferOverflowCheck.check(methodBody, 'testUncheckedMalloc');
    
        expect(issues).toContain('Warning: Unchecked return value of "malloc" in "testUncheckedMalloc"');
    });
    


    test('should correctly evaluate size expressions', () => {
        const methodBody = `
            int size1 = 5, size2 = 10;
            int totalSize = size1 + size2;
            char buffer[totalSize];`;
        const issues = bufferOverflowCheck.check(methodBody, 'testSizeExpression');
    
        expect(issues).toContain('Warning: Large stack buffer "buffer" (15 bytes) in "testSizeExpression"');
    });


    test('should correctly parse sizeof() expressions', () => {
        const methodBody = `
            char buffer[20]; 
            int size = sizeof(buffer);
            memcpy(buffer, input, size);`;
        const methodName = 'testSizeofExpression';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toEqual([]); // Should not trigger a warning since sizeof() is valid
    });
    
    test('should return null for invalid arithmetic expressions', () => {
        const methodBody = `
            char buffer[10]; 
            int size = bufferSize / 0; 
            memcpy(buffer, input, size);`;
        const methodName = 'testInvalidArithmetic';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toContain('Warning: Untrusted allocation size "size" in "testInvalidArithmetic"');
    });
    

    
    test('should return null for sizeof() on unknown variable', () => {
        const methodBody = `
            int size = sizeof(unknownVar);
            char buffer[size];`;
        const methodName = 'testUnknownSizeof';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toContain('Warning: Untrusted allocation size "size" in "testUnknownSizeof"');
    });

    
    test('should not flag malloc when allocation size is validated', () => {
        const code = `
            int size = 256;
            if (size < 512) {
                char *ptr = malloc(size);
            }
        `;
        const result = checker.check(code, 'safeMallocMethod');
        expect(result).toEqual([]);
    });
    



    test('should not flag malloc when allocation size is validated', () => {
        const code = `
            int size = 256;
            if (size < 512) {
                char *ptr = malloc(size);
            }
        `;
        const result = checker.check(code, 'safeMallocMethod');
        expect(result).toEqual([]);
    });

    
    test('should detect pointer arithmetic on buffer', () => {
        const code = `
            char buffer[10];
            buffer += 5;
        `;
        const result = checker.check(code, 'pointerArithmeticMethod');
        expect(result).toContain(
            'Warning: Pointer arithmetic on buffer "buffer" in "pointerArithmeticMethod"'
        );
    });
    


    test('should correctly handle sizeof() expression in allocation', () => {
        const code = `
            char buffer[256];
            int size = sizeof(buffer);
            char *ptr = malloc(size);
        `;
        const result = checker.check(code, 'sizeofMethod');
        expect(result).toEqual([]); // Since size is correctly derived from sizeof()
    });

    test('should correctly handle sizeof() expression', () => {
        const methodBody = `
            int bufferSize = sizeof(myBuffer);
            char buffer[bufferSize];
        `;
        const methodName = 'testSizeofExpression';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        // If `myBuffer` is not defined in `variables`, it should return `null`
        expect(issues).toContain('Warning: Untrusted allocation size "bufferSize" in "testSizeofExpression"');
    });

    const testCases = [
        "sizeof(myBuffer)",
        "sizeof( buffer )",
        "sizeof(int)",
        "sizeof (char*)",
        "sizeof   (myArray)"
    ];
    
    const regex = /sizeof\s*\(\s*(.+?)\s*\)/;
    
    testCases.forEach(test => {
        const match = regex.exec(test);
        console.log(`Test: ${test}, Match:`, match);
    });
    
    
    test('should return null for sizeof() on unknown variable', () => {
        const methodBody = `
            int size = sizeof(unknownVar);
            char buffer[size];`;
        const methodName = 'testUnknownSizeof';
        const issues = bufferOverflowCheck.check(methodBody, methodName);
    
        expect(issues).toContain('Warning: Untrusted allocation size "size" in "testUnknownSizeof"');
    });
    
    
    

});
