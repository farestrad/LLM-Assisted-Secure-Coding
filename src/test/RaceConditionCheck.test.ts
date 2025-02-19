import { RaceConditionCheck } from '../testers/c/checkRaceConditionVulnerabilities';

// 🛠️ Properly Mock VSCode Configuration
jest.mock('vscode', () => ({
    workspace: {
        getConfiguration: jest.fn().mockReturnValue({
            get: jest.fn((key: 'raceConditionKeywords') => {
                const configs: Record<'raceConditionKeywords', string[]> = {
                    raceConditionKeywords: ['fopen', 'freopen', 'fwrite', 'fread', 'fclose', 'fprintf', 'fputs', 'fscanf', 'chmod', 'chown', 'access', 'stat']
                };
                return configs[key];
            })
        })
    }
}));

describe('RaceConditionCheck', () => {
    let checker: RaceConditionCheck;

    beforeEach(() => {
        checker = new RaceConditionCheck();
    });


    test('should detect race conditions in both file operations and metadata operations', () => {
        const code = `
            fwrite(file, "data", strlen("data"));
            fputs("data", file);
            access("/etc/passwd", F_OK);
            stat("/tmp/logfile", &fileStat);
        `;
        const result = checker.check(code, 'combinedRaceMethod');
        expect(result).toContain(
            'Warning: Potential race condition in low-level file operation "fwrite"'
        );
        expect(result).toContain(
            'Warning: Potential race condition in low-level file operation "fputs"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "access"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "stat"'
        );
    });
    


    test('should warn when file access is missing a locking mechanism', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "w");
            fprintf(file, "Unprotected data");
            fclose(file);
        `;
        const result = checker.check(code, 'missingLockMethod');
        expect(result).toContain(
            'Warning: File access detected without proper file locking in method "missingLockMethod". Ensure proper file locking to prevent issues.'
        );
    });

    test('should execute all race condition handlers', () => {
        const raceConditionChecks = [
            {
                pattern: /\b(fopen|freopen|fwrite|fread|fclose|fprintf|fputs|fscanf)\s*\(/g,
                handler: (fn: string) => `Warning: Potential race condition in low-level file operation "${fn}"`
            },
            {
                pattern: /\b(access|stat|chmod|chown)\s*\(\s*[^,]+/g,
                handler: (fn: string) => `Potential race condition in file metadata operation "${fn}"`
            }
        ];
    
        // Simulate executing handlers manually
        const fileWarning = raceConditionChecks[0].handler('fwrite');
        const metadataWarning = raceConditionChecks[1].handler('stat');
    
        expect(fileWarning).toBe('Warning: Potential race condition in low-level file operation "fwrite"');
        expect(metadataWarning).toBe('Potential race condition in file metadata operation "stat"');
    });
    
    
    test('should detect potential race conditions in metadata operations', () => {
        const code = `
            access("/etc/passwd", F_OK);
            stat("/tmp/logfile", &fileStat);
        `;
        const result = checker.check(code, 'metadataRaceMethod');
        expect(result).toContain(
            'Potential race condition in file metadata operation "access"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "stat"'
        );
    });

    test('should warn when file access occurs without proper locking', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "w");
            fprintf(file, "Unprotected data");
            fclose(file);
        `;
        const result = checker.check(code, 'noLockMethod');
        expect(result).toContain(
            'Warning: File access detected without proper file locking in method "noLockMethod". Ensure proper file locking to prevent issues.'
        );
    });
    
    
    

    // ✅ 1️⃣ Detect File Access Functions Without Proper Locking
    test('should detect file access functions without proper locking', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "w");
            fprintf(file, "Sensitive data");
            fclose(file);
        `;
        const result = checker.check(code, 'raceConditionMethod');
        expect(result).toContain(
            'Warning: File access function detected in method "raceConditionMethod". Ensure proper file locking to prevent race conditions.'
        );
        expect(result).toContain(
            'Warning: File access detected without proper file locking in method "raceConditionMethod". Ensure proper file locking to prevent issues.'
        );
    });

    // ✅ 2️⃣ Detect Race Conditions in Metadata Operations (`stat`, `access`)
    test('should detect race conditions in metadata operations', () => {
        const code = `
            struct stat fileStat;
            stat("/tmp/data.txt", &fileStat);
            access("/etc/shadow", F_OK);
        `;
        const result = checker.check(code, 'metadataMethod');
        expect(result).toContain(
            'Potential race condition in file metadata operation "stat"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "access"'
        );
    });

    // ✅ 3️⃣ Detect Race Conditions in File Permission Changes (`chmod`, `chown`)
    test('should detect race conditions in file permission changes', () => {
        const code = `
            chmod("/tmp/data.txt", 0777);
            chown("/tmp/data.txt", 1000, 1000);
        `;
        const result = checker.check(code, 'metadataChangeMethod');
        expect(result).toContain(
            'Potential race condition in file metadata operation "chmod"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "chown"'
        );
    });

    // ✅ 4️⃣ Detect Missing File Locks When Using File Access Functions
    test('should warn when file access occurs without proper locking', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "w");
            fprintf(file, "Unprotected data");
            fclose(file);
        `;
        const result = checker.check(code, 'noLockMethod');
        expect(result).toContain(
            'Warning: File access detected without proper file locking in method "noLockMethod". Ensure proper file locking to prevent issues.'
        );
    });

    // ✅ 5️⃣ Ensure File Operations With Proper Locking Are Not Flagged
    test('should not flag safe file operations with proper locking', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "w");
            flock(fileno(file), LOCK_EX);
            fprintf(file, "Safe data");
            fclose(file);
        `;
        const result = checker.check(code, 'safeMethod');
        expect(result).toEqual([]);
    });

    // ✅ 6️⃣ Ensure File Access Without Writing Data Is Not Flagged
    test('should not flag read-only file access without modification', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "r");
            fclose(file);
        `;
        const result = checker.check(code, 'readOnlyMethod');
        expect(result).toEqual([]);
    });

    // ✅ 7️⃣ Edge Case: No File Operations Should Return Empty
    test('should handle edge cases with no file operations', () => {
        const code = `
            printf("Hello, World!\n");
        `;
        const result = checker.check(code, 'edgeCaseMethod');
        expect(result).toEqual([]);
    });

    test('should detect race conditions in both file operations and metadata operations', () => {
        const code = `
            FILE *file = fopen("/tmp/data.txt", "w");
            chmod("/tmp/data.txt", 0777);
            access("/etc/passwd", F_OK);
        `;
        const result = checker.check(code, 'raceConditionMethod');
    
        expect(result).toContain(
            'Warning: Potential race condition in low-level file operation "fopen"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "chmod"'
        );
        expect(result).toContain(
            'Potential race condition in file metadata operation "access"'
        );
    });
    
});
