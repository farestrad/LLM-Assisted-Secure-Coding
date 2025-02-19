import { RandomNumberGenerationCheck } from '../testers/c/checkRandomNumberGeneration';
import * as vscode from 'vscode';

// Mock vscode configuration to return the expected arrays
jest.mock('vscode', () => ({
  workspace: {
    getConfiguration: jest.fn().mockReturnValue({
      get: jest.fn().mockImplementation((key: string, defaultValue: any) => {
        switch (key) {
          case 'secureRandomFunctions':
            return ['rand_s', 'rand_r', 'random_r', 'arc4random', 'getrandom', 'CryptGenRandom'];
          case 'secureSeeds':
            return ['getrandom', 'CryptGenRandom'];
          case 'loopFunctions':
            return ['rand', 'random', 'drand48', 'lrand48'];
          default:
            return defaultValue;
        }
      })
    })
  }
}));

describe('RandomNumberGenerationCheck', () => {
  let checker: RandomNumberGenerationCheck;

  beforeEach(() => {
    checker = new RandomNumberGenerationCheck();
  });

  test('detects insecure random number generator "rand()"', () => {
    const methodBody = `
      int a = rand();
    `;
    const issues = checker.check(methodBody, 'testMethod');
    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining('Warning: Insecure random number generator "rand" detected in method "testMethod"')
    ]));
  });

  test('detects insecure seeding with time(NULL)', () => {
    const methodBody = `
      srand(time(NULL));
    `;
    const issues = checker.check(methodBody, 'seedMethod');
    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining('Warning: Using time(NULL) as a seed is insecure in method "seedMethod"')
    ]));
  });

  test('detects insecure RNG used inside a loop', () => {
    const methodBody = `
      for (int i = 0; i < 10; i++) {
        int r = random();
      }
    `;
    const issues = checker.check(methodBody, 'loopMethod');

    // Because the check flags insecure functions in two phases (phase 1 and phase 3),
    // we expect at least one warning mentioning the function name and the loop.
    const hasLoopWarning = issues.some(issue => 
      issue.includes('random') && issue.includes('detected in a loop')
    );
    expect(hasLoopWarning).toBe(true);
  });

  test('context analysis: flags insecure call with argument in "rand(...)"', () => {
    const methodBody = `
      int x = rand(123);
    `;
    const issues = checker.check(methodBody, 'contextRandMethod');

    // Expect a warning from context analysis (phase 4/5) that checks the argument.
    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining('Insecure seed source "123" for rand')
    ]));
  });

  test('context analysis: flags insecure seed in "srand" with non-secure seed', () => {
    const methodBody = `
      srand(12345);
    `;
    const issues = checker.check(methodBody, 'contextSeedMethod');
    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining('Insecure seed source "12345" for srand')
    ]));
  });

  test('context analysis: does not flag secure seed in "srand"', () => {
    const methodBody = `
      srand(getrandom);
    `;
    const issues = checker.check(methodBody, 'secureSeedMethod');
    // Since "getrandom" is in the list of secureSeeds, no context warning should be generated.
    // (Also note that phase 2 only catches srand(time(NULL)) so this should pass without warnings.)
    expect(issues).not.toEqual(expect.arrayContaining([
      expect.stringContaining('srand')
    ]));
  });

  test('does not warn for secure random functions', () => {
    const methodBody = `
      int secureValue = rand_s();
    `;
    const issues = checker.check(methodBody, 'secureRandMethod');
    // "rand_s" is in the secure list and not in the "loopFunctions" array so no warnings should be generated.
    expect(issues).toHaveLength(0);
  });

  test('does not produce false positives for similar function names', () => {
    const methodBody = `
      int val = custom_random(10);
    `;
    const issues = checker.check(methodBody, 'falsePositiveMethod');
    // The regex should only match whole words from loopFunctions.
    expect(issues).toHaveLength(0);
  });

  test('produces multiple warnings for multiple insecure usages', () => {
    const methodBody = `
      int a = rand();
      srand(time(NULL));
      for (int i = 0; i < 5; i++) {
        int r = drand48();
      }
      srand(9999);
      int b = random(42);
    `;
    const issues = checker.check(methodBody, 'multiIssueMethod');

    // We expect warnings from various phases:
    // - Insecure random generator "rand" (phase 1)
    // - Insecure seeding with time(NULL) (phase 2)
    // - Insecure RNG "drand48(" detected in a loop (phase 3)
    // - Context analysis flag for srand(9999)
    // - Insecure random generator "random" (phase 1) plus possibly a context analysis warning if applicable.
    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining('Warning: Insecure random number generator "rand" detected in method "multiIssueMethod"'),
      expect.stringContaining('Warning: Using time(NULL) as a seed is insecure in method "multiIssueMethod"'),
      expect.stringContaining('Warning: Insecure RNG "drand48(" detected in a loop in method "multiIssueMethod"'),
      expect.stringContaining('Insecure seed source "9999" for srand'),
      expect.stringContaining('Warning: Insecure random number generator "random" detected in method "multiIssueMethod"')
    ]));
  });
});
