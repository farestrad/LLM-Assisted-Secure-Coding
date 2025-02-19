import { PathTraversalCheck } from '../testers/c/checkPathTraversalVulnerabilities';

// 🛠️ Mock VSCode Configuration
type ConfigKeys = 'pathTraversalPatterns' | 'riskyFunctions' | 'fileOperations';

jest.mock('vscode', () => ({
    workspace: {
        getConfiguration: jest.fn().mockReturnValue({
            get: jest.fn((key: ConfigKeys) => {
                const configs: Record<ConfigKeys, string[]> = {
                    pathTraversalPatterns: ['../', '~/', '\\..\\'],
                    riskyFunctions: ['fopen', 'readfile', 'unlink'],
                    fileOperations: ['open', 'read', 'unlink']
                };
                return configs[key]; // Now TypeScript recognizes this as valid
            })
        })
    }
}));


describe('PathTraversalCheck', () => {
    let checker: PathTraversalCheck;

    beforeEach(() => {
        checker = new PathTraversalCheck();
    });

    //  Path Traversal Pattern Detection
    test('should detect various path traversal patterns', () => {
        const code = `
            char *path1 = "../etc/passwd";
            char *path2 = "~/private_key";
            char *path3 = "\\..\\secret.txt";
        `;
        const result = checker.check(code, 'pathPatternMethod');
        expect(result).toContain(
            'Warning: Potential Path Traversal vulnerability detected in method "pathPatternMethod". Avoid using relative paths with user input.'
        );
    });

    //  Risky Function Calls (e.g., fopen, unlink)
    test('should detect risky function calls with unsafe arguments', () => {
        const code = `
            unlink("../config");
            readfile(user_input);
        `;
        const result = checker.check(code, 'riskyFunctionMethod');
        expect(result).toContain(
            'Warning: Path traversal vulnerability detected in function "unlink" in method "riskyFunctionMethod" with argument "../config". Avoid using relative paths with user input.'
        );
        expect(result).toContain(
            'Warning: Path traversal vulnerability detected in function "readfile" in method "riskyFunctionMethod" with argument "user_input". Avoid using relative paths with user input.'
        );
    });

    //  Unsanitized Input in File Operations
    test('should detect unsanitized input in file operations', () => {
        const code = `
            open(user_input, O_RDONLY);
        `;
        const result = checker.check(code, 'unsanitizedInputMethod');
        expect(result).toContain(
            'Warning: Unsanitized input "user_input" detected in file operation in method "unsanitizedInputMethod". Ensure input is sanitized before use.'
        );
    });

    //  Command Execution (`exec`, `system`)
    test('should detect command execution with user input', () => {
        const code = `
            exec("rm -rf " + user_input);
            system("ls " + input);
            popen("cat " + path, "r");
        `;
        const result = checker.check(code, 'commandExecutionMethod');
        expect(result).toContain(
            'Warning: Potential path traversal vulnerability detected in function "exec" with argument "rm -rf " + user_input in method "commandExecutionMethod". Avoid using relative paths with user input.'
        );
    });

    //  PHP File Inclusion (`include`, `require`)
    test('should detect insecure PHP includes and requires', () => {
        const code = `
            include(user_input);
            require("../config.php");
        `;
        const result = checker.check(code, 'phpIncludeMethod');
        expect(result).toContain(
            'Warning: Potential path traversal vulnerability detected in function "include" with argument "user_input" in method "phpIncludeMethod". Avoid using relative paths with user input.'
        );
    });

    //  Sanitized Inputs Should NOT Trigger Warnings
    test('should not flag sanitized inputs', () => {
        const code = `
            char *path = realpath(user_input, NULL);
            fopen(path, "r");
        `;
        const result = checker.check(code, 'sanitizedMethod');
        expect(result).toEqual([]); // No warning should be triggered
    });

    //  Safe File Operations Should NOT Be Flagged
    test('should not flag safe file operations', () => {
        const code = `
            fopen("/var/log/syslog", "r");
        `;
        const result = checker.check(code, 'safeMethod');
        expect(result).toEqual([]);
    });

    // Edge Case: No File Operations Present
    test('should handle edge cases with no file operations', () => {
        const code = `
            printf("Hello, World!\n");
        `;
        const result = checker.check(code, 'edgeCaseMethod');
        expect(result).toEqual([]);
    });



    test('should detect path traversal in various formats', () => {
        const code = `
            char *path1 = "../etc/passwd";
            char *path2 = "~/user/.ssh/id_rsa";
            char *path3 = "/var/www/../../config";
        `;
        const result = checker.check(code, 'pathTraversalTest');
    
        expect(result).toContain(
            'Warning: Potential Path Traversal vulnerability detected in method "pathTraversalTest". Avoid using relative paths with user input.'
        );
    });
    
});


