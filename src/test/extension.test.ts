import { IntegerFlowCheck } from '../testers/c/checkIntegerOverflowUnderflow'; // Adjust the path accordingly
describe('IntegerFlowCheck', () => {
    let checker: any;

    beforeEach(() => {
        checker = new IntegerFlowCheck();
    });

    test('should detect integer overflow', () => {
        const methodBody = 'x = 9007199254740991 + 1;'; // MAX_SAFE_INTEGER + 1
        const result = checker.check(methodBody, 'testMethod');
        expect(result.length).toBeGreaterThan(0);
    });

    test('should detect integer underflow', () => {
        const methodBody = 'y = -9007199254740991 - 2;'; // MIN_SAFE_INTEGER - 1
        const result = checker.check(methodBody, 'testMethod');
        expect(result.length).toBeGreaterThan(0);
    });

    test('should not flag safe operations', () => {
        const methodBody = 'z = 100 + 50;';
        const result = checker.check(methodBody, 'testMethod');
        expect(result.length).toBe(0);
    });
});