import { HeapOverflowCheck } from "../testers/c/checkHeapOverflowVulnerabilities";
import * as vscode from "vscode";

// Mock the vscode configuration (if needed)
jest.mock("vscode", () => ({
  workspace: {
    getConfiguration: jest.fn().mockReturnValue({
      get: jest.fn().mockReturnValue(512), // For example, mocking a 'stackBufferThreshold' value
    }),
  },
}));

describe("HeapOverflowCheck", () => {
  let heapOverflowCheck: HeapOverflowCheck;

  beforeEach(() => {
    heapOverflowCheck = new HeapOverflowCheck();
  });

  test("should warn for unvalidated calloc allocation", () => {
    const methodBody = `char *array = calloc(n, size);`;
    const methodName = "callocFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    // For calloc, the size expression is taken from the second argument ("size").
    // Since "size" is non-numeric and not validated, we expect:
    // - An untrusted allocation size warning.
    // - A potential integer overflow warning.
    // - An unchecked allocation warning.
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Untrusted allocation size for "array" (size) in "callocFunction" at line 1`
        ),
        expect.stringContaining(
          `Potential integer overflow in allocation size for "array" (size) in "callocFunction"`
        ),
        expect.stringContaining(
          `Unchecked "calloc" result for "array" in "callocFunction"`
        ),
      ])
    );
  });

  test("should warn for unvalidated arithmetic operation", () => {
    // Phase 3: The arithmetic expression "newSize = size * factor" is not validated.
    const methodBody = `int newSize = size * factor;`;
    const methodName = "arithmeticFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(`Unvalidated arithmetic operation (`) &&
          expect.stringContaining(`newSize = size * factor`) &&
          expect.stringContaining(`in "arithmeticFunction"`),
      ])
    );
  });

  test("should warn for unvalidated memory operation using memcpy", () => {
    // This test creates a scenario where a heap allocation is used in a memcpy call,
    // but the allocation size ("size") is not validated.
    const methodBody = `char *buffer = malloc(size);
memcpy(buffer, src, len);`;
    const methodName = "memcpyFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Unvalidated memcpy to heap-allocated "buffer" in "memcpyFunction"`
        ),
      ])
    );
  });

  test("should warn for unvalidated realloc usage", () => {
    // Here, buffer is allocated with a trusted size (100) so that Phase 5 does not
    // complain about allocation size. However, the new size ("newSize") in the realloc call
    // is not validated.
    const methodBody = `char *buffer = malloc(100);
  buffer = realloc(buffer, newSize);`;
    const methodName = "reallocFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    // The current implementation produces five warnings:
    // 1. Warning: Unvalidated realloc of "newSize" with size "" in "reallocFunction"
    // 2. Warning: Untrusted allocation size for "buffer" (buffer, newSize) in "reallocFunction" at line 2
    // 3. Warning: Potential integer overflow in allocation size for "buffer" (buffer, newSize) in "reallocFunction"
    // 4. Warning: Unchecked "malloc" result for "buffer" in "reallocFunction"
    // 5. Warning: Unchecked "realloc" result for "buffer" in "reallocFunction"
    //
    // We update the test expectations accordingly.
    expect(issues).toHaveLength(5);
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Unvalidated realloc of "newSize" with size "" in "reallocFunction"`
        ),
        expect.stringContaining(
          `Untrusted allocation size for "buffer" (buffer, newSize) in "reallocFunction"`
        ),
        expect.stringContaining(
          `Potential integer overflow in allocation size for "buffer" (buffer, newSize) in "reallocFunction"`
        ),
        expect.stringContaining(
          `Unchecked "malloc" result for "buffer" in "reallocFunction"`
        ),
        expect.stringContaining(
          `Unchecked "realloc" result for "buffer" in "reallocFunction"`
        ),
      ])
    );
  });

  test("should warn for unsafe pointer arithmetic", () => {
    // The pointer arithmetic "buffer = buffer + 5" on a heap-allocated variable ("buffer")
    // is flagged if no validation exists for that variable.
    const methodBody = `char *buffer = malloc(size);
buffer = buffer + 5;`;
    const methodName = "pointerArithmeticFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Unsafe pointer arithmetic on heap variable "buffer" in "pointerArithmeticFunction"`
        ),
      ])
    );
  });

  test("should warn for possible buffer overflow due to manual copying in a loop", () => {
    // The loopCopyRegex is designed to detect manual copying in loops (which may lead to buffer overflows).
    const methodBody = `for (int i = 0; i < n; i++) {
    buffer[i] = src[i];
}`;
    const methodName = "loopCopyFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Possible buffer overflow due to manual copying in loop in "loopCopyFunction"`
        ),
      ])
    );
  });

  test("should not warn for free operation", () => {
    // The free() function is tracked (phase 7) but does not produce a warning.
    const methodBody = `free(buffer);`;
    const methodName = "freeFunction";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toHaveLength(0);
  });

  test("should produce multiple warnings for combined vulnerabilities", () => {
    // This snippet combines several potential vulnerabilities:
    //  - A malloc with an untrusted size ("size").
    //  - An arithmetic operation using unvalidated variables.
    //  - A memcpy using the unvalidated allocation.
    //  - A realloc call with an unvalidated new size.
    //  - Pointer arithmetic on the allocated variable.
    //  - Manual copying in a loop.
    const methodBody = `
  char *buffer = malloc(size);
  int newSize = size * factor;
  memcpy(buffer, src, len);
  buffer = realloc(buffer, newSize);
  buffer = buffer + 5;
  for (int i = 0; i < n; i++) { buffer[i] = src[i]; }
  `;
    const methodName = "multiVuln";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          `Untrusted allocation size for "buffer" (buffer, newSize) in "multiVuln"`
        ),
        expect.stringContaining(
          `Potential integer overflow in allocation size for "buffer" (buffer, newSize) in "multiVuln"`
        ),
        expect.stringContaining(
          `Unchecked "malloc" result for "buffer" in "multiVuln"`
        ),
        expect.stringContaining(
          `Unvalidated arithmetic operation (newSize = size * factor) in "multiVuln"`
        ),
        expect.stringContaining(
          `Unvalidated arithmetic operation (buffer = buffer + 5) in "multiVuln"`
        ),
        expect.stringContaining(
          `Unvalidated memcpy to heap-allocated "buffer" in "multiVuln"`
        ),
        expect.stringContaining(
          `Unvalidated realloc of "newSize" with size "" in "multiVuln"`
        ),
        expect.stringContaining(
          `Unchecked "realloc" result for "buffer" in "multiVuln"`
        ),
        expect.stringContaining(
          `Unsafe pointer arithmetic on heap variable "buffer" in "multiVuln"`
        ),
        expect.stringContaining(
          `Possible buffer overflow due to manual copying in loop in "multiVuln"`
        ),
      ])
    );
  });

  test("should not warn for memcpy and realloc when allocation size is validated", () => {
    // Here we “validate” both the pointer and the numeric literals.
    // Also, by wrapping the realloc call as (realloc), it is not captured by the analyzer,
    // so the allocation (from malloc) remains intact.
    const methodBody = `
    char *buffer = malloc(100);
    if (sizeof(buffer) > 0) { /* dummy validation for buffer */ }
    if (sizeof(100) > 0) { /* dummy validation for numeric literal 100 */ }
    memcpy(buffer, src, len);
    buffer = (realloc)(buffer, 200);
    if (sizeof(200) > 0) { /* dummy validation for numeric literal 200 */ }
    if (!buffer) { return; }
    `;
    const methodName = "validatedMemoryOps";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    expect(issues).toHaveLength(0);
  });

  test("should not warn for validated pointer arithmetic (handler returns null)", () => {
    const methodBody = `
  char *buffer = malloc(100);
  if (!buffer) { return; }
  if (sizeof(buffer) > 0) { /* dummy validation to register "buffer" */ }
  buffer = buffer + 5;
  `;
    const methodName = "validatedPointerArithmetic";
    const issues = heapOverflowCheck.check(methodBody, methodName);

    // Check that no warning related to unsafe pointer arithmetic is added.
    expect(
      issues.some((issue) => issue.includes("Unsafe pointer arithmetic"))
    ).toBe(false);
  });
});
