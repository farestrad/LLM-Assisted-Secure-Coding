import { WeakHashingEncryptionCheck } from '../testers/c/analyzeCodeForWeakHashingAndEncryption'; 
describe('WeakHashingEncryptionCheck', () => {
    let checker: WeakHashingEncryptionCheck;

    beforeEach(() => {
        checker = new WeakHashingEncryptionCheck();
    });

    test('should detect weak hashing algorithms (MD5, SHA1)', () => {
        const code = `
            char hash[32];
            hash = MD5("password");
            hash = SHA1("data");
        `;
        const result = checker.check(code, 'testMethod');
        expect(result).toContain(
            'Warning: Weak hashing algorithm (MD5) detected in method "testMethod". Consider using a strong hash function like bcrypt, scrypt, or Argon2.'
        );
        expect(result).toContain(
            'Warning: Weak hashing algorithm (SHA1) detected in method "testMethod". Consider using a strong hash function like bcrypt, scrypt, or Argon2.'
        );
    });

    test('should detect insecure encryption methods', () => {
        const code = `
            encrypted = aes_encrypt("password", key);
            data = rsa_encrypt("sensitive_data", key);
        `;
        const result = checker.check(code, 'encryptMethod');
        expect(result).toContain(
            'Warning: Passwords should not be encrypted using aes_encrypt in method "encryptMethod". Use a secure hashing algorithm (e.g., bcrypt, Argon2) instead.'
        );
        expect(result).toContain(
            'Warning: Passwords should not be encrypted using rsa_encrypt in method "encryptMethod". Use a secure hashing algorithm (e.g., bcrypt, Argon2) instead.'
        );
    });

    test('should detect inclusion of insecure hash libraries', () => {
        const code = `#include <openssl/md5.h>`;
        const result = checker.check(code, 'hashLibMethod');
        expect(result).toContain(
            'Warning: Insecure hash library inclusion detected in method "hashLibMethod". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.'
        );
    });

    test('should return empty array when no vulnerabilities are found', () => {
        const code = `
            int secureFunction() {
                // Safe code
                return 0;
            }
        `;
        const result = checker.check(code, 'safeMethod');
        expect(result).toEqual([]);
    });

    test('should handle edge cases with no hashing or encryption present', () => {
        const code = `
            printf("Hello, World!\n");
        `;
        const result = checker.check(code, 'edgeCaseMethod');
        expect(result).toEqual([]);
    });



    //////////


    test('should detect inclusion of SHA-1 hash library', () => {
        const code = `#include <openssl/sha.h>`;
        const result = checker.check(code, 'hashLibSHA1Method');
        expect(result).toContain(
            'Warning: Insecure hash library inclusion detected in method "hashLibSHA1Method". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.'
        );
    });

    

    test('should return empty array when no vulnerabilities are found', () => {
        const code = `
            int secureFunction() {
                // Safe code
                return 0;
            }
        `;
        const result = checker.check(code, 'safeMethod');
        expect(result).toEqual([]);
    });

    

    test('should detect inclusion of insecure hash libraries', () => {
        const code = `#include <openssl/md5.h>`;
        const result = checker.check(code, 'hashLibMethod');
        expect(result).toContain(
            'Warning: Insecure hash library inclusion detected in method "hashLibMethod". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.'
        );
    });

    

    test('should detect inclusion of SHA-1 hash library', () => {
        const code = `#include <openssl/sha.h>`;
        const result = checker.check(code, 'hashLibSHA1Method');
        expect(result).toContain(
            'Warning: Insecure hash library inclusion detected in method "hashLibSHA1Method". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.'
        );
    });
    


    test('should detect weak hashing with different naming variations', () => {
        const code = `
            char hash[32];
            hash = md5_hash("password");
            hash = sha1sum("data");
        `;
        const result = checker.check(code, 'testMethodVaried');
        expect(result).toContain(
            'Warning: Weak hashing algorithm (md5) detected in method "testMethodVaried". Consider using a strong hash function like bcrypt, scrypt, or Argon2.'
        );
        expect(result).toContain(
            'Warning: Weak hashing algorithm (sha1) detected in method "testMethodVaried". Consider using a strong hash function like bcrypt, scrypt, or Argon2.'
        );
    });
    


    test('should not flag strong encryption usage', () => {
        const code = `
            char encrypted[64];
            encrypted = AES_256_encrypt("data", key);
        `;
        const result = checker.check(code, 'secureEncryptionMethod');
        expect(result).toEqual([]); // Should NOT trigger a warning
    });

    test('should not flag methods without insecure hash library includes', () => {
        const code = `
            #include <openssl/aes.h>  // Safe library
            void secureFunction() {
                printf("No weak hashes here.");
            }
        `;
        const result = checker.check(code, 'safeHashMethod');
        expect(result).toEqual([]); // No warning should be triggered
    });


    test('should detect insecure OpenSSL hash library inclusion', () => {
        const code = `
            #include <openssl/md5.h>
            #include "openssl/sha.h"
        `;
        const result = checker.check(code, 'testInsecureLibrary');
    
        expect(result).toContain(
            'Warning: Insecure hash library inclusion detected in method "testInsecureLibrary". Avoid using MD5 or SHA-1 from OpenSSL or similar libraries for password hashing.'
        );
    });
    
    
    

});
