import { InfiniteLoopCheck } from '../testers/c/checkInfiniteLoopsOrExcessiveResourceConsumption';

describe('InfiniteLoopCheck', () => {
    let checker: InfiniteLoopCheck;

    beforeEach(() => {
        checker = new InfiniteLoopCheck();
    });

    test('should detect potential infinite loops', () => {
        const code = `
            while (true) {
                // infinite loop
            }
            for (;;) {
                // another infinite loop
            }
        `;
        const result = checker.check(code, 'infiniteLoopMethod');
        expect(result).toContain(
            'Warning: Potential infinite loop detected in method "infiniteLoopMethod" at position 13. Ensure proper termination conditions.'
        );
        expect(result).toContain(
            'Warning: Potential infinite loop detected in method "infiniteLoopMethod" at position 58. Ensure proper termination conditions.'
        );
    });

    test('should detect excessive memory allocations', () => {
        const code = `
            char* buffer = (char*) malloc(2097152); // 2 MB allocation
            int* array = (int*) calloc(1, 524288);  // Large calloc allocation
        `;
        const result = checker.check(code, 'memoryAllocationMethod');
        expect(result).toContain(
            'Warning: Excessive memory allocation (2097152 bytes) detected in method "memoryAllocationMethod". Review memory usage.'
        );
        expect(result).toContain(
            'Warning: Excessive memory allocation (524288 bytes) detected in method "memoryAllocationMethod". Review memory usage.'
        );
    });

    test('should not flag normal loops or small memory allocations', () => {
        const code = `
            for (int i = 0; i < 10; i++) {}
            while (condition) {}
            char* buffer = (char*) malloc(1024); // 1 KB allocation
        `;
        const result = checker.check(code, 'safeMethod');
        expect(result).toEqual([]);
    });

    test('should handle edge cases with no loops or allocations', () => {
        const code = `
            printf("Hello, World!\n");
        `;
        const result = checker.check(code, 'edgeCaseMethod');
        expect(result).toEqual([]);
    });

    test('should detect infinite loops with different structures', () => {
        const code = `
            do { } while (true);
            while (1) { /* Infinite loop with constant */ }
        `;
        const result = checker.check(code, 'loopVariationsMethod');
        expect(result).toContain(
            'Warning: Potential infinite loop detected in method "loopVariationsMethod". Ensure proper termination conditions.'
        );
    });
    

});
