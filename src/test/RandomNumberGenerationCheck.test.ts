import { RandomNumberGenerationCheck } from '../testers/c/checkRandomNumberGeneration';

// Mock vscode configuration with proper array returns
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

    test('detects insecure random number generator rand()', () => {
        const methodBody = `
            int randomValue = rand();
        `;
        const methodName = 'testMethod';

        const issues = checker.check(methodBody, methodName);

        expect(issues).toContain(
            expect.stringContaining('Warning: Insecure random number generator "rand" detected')
        );
    });

});