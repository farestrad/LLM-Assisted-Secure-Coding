import { IntegerFlowCheck } from '../testers/c/checkIntegerOverflowUnderflow'; // Adjust this path as needed

describe('IntegerFlowCheck', () => {
  let checkInstance: IntegerFlowCheck;

  beforeEach(() => {
    checkInstance = new IntegerFlowCheck();
  });

  test('should not report vulnerability for safe addition', () => {
    const methodBody = "a = 5 + 6;";
    const methodName = "safeAddition";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should report vulnerability for addition overflow', () => {
    // 9007199254740991 is Number.MAX_SAFE_INTEGER;
    // adding 1 causes the result to be 9007199254740992, which is unsafe.
    const methodBody = "a = 9007199254740991 + 1;";
    const methodName = "overflowAddition";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues.length).toBe(1);
    expect(issues[0]).toContain('Warning: Integer overflow/underflow detected for variable "a"');
    expect(issues[0]).toContain('9007199254740991 + 1');
  });

  test('should report vulnerability for subtraction underflow', () => {
    // -9007199254740991 is Number.MIN_SAFE_INTEGER;
    // subtracting 1 gives -9007199254740992, which is below the safe bound.
    const methodBody = "b = -9007199254740991 - 1;";
    const methodName = "underflowSubtraction";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues.length).toBe(1);
    expect(issues[0]).toContain('Warning: Integer overflow/underflow detected for variable "b"');
    expect(issues[0]).toContain('-9007199254740991 - 1');
  });

  test('should not report vulnerability for safe subtraction', () => {
    const methodBody = "g = 10 - 5;";
    const methodName = "safeSubtraction";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should report vulnerability for multiplication overflow', () => {
    // Multiply two numbers so that the result exceeds Number.MAX_SAFE_INTEGER.
    const methodBody = "c = 10000000000000000 * 2;";
    const methodName = "multiplicationOverflow";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues.length).toBe(1);
    expect(issues[0]).toContain('Warning: Integer overflow/underflow detected for variable "c"');
    expect(issues[0]).toContain('10000000000000000 * 2');
  });

  test('should not report vulnerability for safe division', () => {
    const methodBody = "e = 100 / 2;";
    const methodName = "safeDivision";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should not report vulnerability for division by zero', () => {
    // When dividing by zero, the check sets result to null and no warning is issued.
    const methodBody = "d = 10 / 0;";
    const methodName = "divisionByZero";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should handle negative numbers correctly', () => {
    // The operation "5 - -3" equals 8, which is a safe value.
    const methodBody = "h = 5 - -3;";
    const methodName = "negativeNumbers";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should not match non-arithmetic assignments', () => {
    // This assignment should not trigger the regex (e.g. a variable declaration).
    const methodBody = "let x = 42;";
    const methodName = "nonArithmetic";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should not report vulnerability when result equals MAX_INT', () => {
    // 9007199254740990 + 1 equals exactly Number.MAX_SAFE_INTEGER (9007199254740991)
    const methodBody = "f = 9007199254740990 + 1;";
    const methodName = "edgeMax";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should not report vulnerability when result equals MIN_INT', () => {
    // -9007199254740990 - 1 equals exactly Number.MIN_SAFE_INTEGER (-9007199254740991)
    const methodBody = "g = -9007199254740990 - 1;";
    const methodName = "edgeMin";
    const issues = checkInstance.check(methodBody, methodName);
    expect(issues).toEqual([]);
  });

  test('should report multiple vulnerabilities in a single method body', () => {
    // In a method body with several operations, only the ones causing over/underflow should be reported.
    const methodBody = `
      a = 9007199254740991 + 1;
      b = -9007199254740991 - 1;
      c = 50 * 2;
    `;
    const methodName = "multipleIssues";
    const issues = checkInstance.check(methodBody, methodName);
    // Only the first two operations produce warnings.
    expect(issues.length).toBe(2);
    expect(issues[0]).toContain('variable "a"');
    expect(issues[1]).toContain('variable "b"');
  });
});
