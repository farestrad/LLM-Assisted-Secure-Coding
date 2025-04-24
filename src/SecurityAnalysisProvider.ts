import * as vscode from 'vscode';
import { runCTests } from './testers/cTester';
import { GeneratedCodeProvider } from './generatedCodeProvider';

// Define the CWE type for better structure
export type CWE = {
    id: number;
    name: string;
    description: string;
};

// Complete list of CWEs referenced in the mappings
export const CWE_DATABASE: { [id: number]: CWE } = {
    // Input Validation
    20: {
        id: 20,
        name: "Improper Input Validation",
        description: "The application does not validate or incorrectly validates input that can affect the control flow or data flow of a program."
    },
    
    // Path Issues
    22: {
        id: 22,
        name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        description: "The application does not properly neutralize special elements within a pathname, allowing attackers to escape outside of the restricted directory."
    },
    23: {
        id: 23,
        name: "Relative Path Traversal",
        description: "The application uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize relative path sequences."
    },
    36: {
        id: 36,
        name: "Absolute Path Traversal",
        description: "The application uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize absolute path sequences."
    },
    73: {
        id: 73,
        name: "External Control of File Name or Path",
        description: "The application allows user input to control or influence paths or file names used in filesystem operations."
    },
    
    // Injection
    78: {
        id: 78,
        name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        description: "The application constructs all or part of an OS command using externally-influenced input without neutralizing special elements."
    },
    89: {
        id: 89,
        name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        description: "The application constructs SQL commands using input from an upstream component without neutralizing special elements."
    },
    94: {
        id: 94,
        name: "Improper Control of Generation of Code ('Code Injection')",
        description: "The application constructs all or part of a code segment using externally-influenced input without properly neutralizing."
    },
    
    // Buffer Issues
    119: {
        id: 119,
        name: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        description: "The application performs operations on a memory buffer, but can read from or write to a memory location outside of the intended boundary."
    },
    120: {
        id: 120,
        name: "Buffer Copy without Checking Size of Input",
        description: "The application copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer."
    },
    122: {
        id: 122,
        name: "Heap-based Buffer Overflow",
        description: "A heap overflow condition is a type of buffer overflow where the buffer that overflows is allocated in the heap portion of memory."
    },
    125: {
        id: 125,
        name: "Out-of-bounds Read",
        description: "The application reads data past the end, or before the beginning, of the intended buffer."
    },
    
    // Credentials
    256: {
        id: 256,
        name: "Plaintext Storage of a Password",
        description: "Storing a password in plaintext may result in a system compromise."
    },
    319: {
        id: 319,
        name: "Cleartext Transmission of Sensitive Information",
        description: "The application transmits sensitive data in cleartext in a communication channel."
    },
    
    // Cryptographic Issues
    327: {
        id: 327,
        name: "Use of a Broken or Risky Cryptographic Algorithm",
        description: "The application uses a broken or risky cryptographic algorithm for sensitive data."
    },
    328: {
        id: 328,
        name: "Use of Weak Hash",
        description: "The application uses a hash algorithm with known weaknesses."
    },
    330: {
        id: 330,
        name: "Use of Insufficiently Random Values",
        description: "The application uses insufficiently random values, causing a protection mechanism to be compromised."
    },
    338: {
        id: 338,
        name: "Use of Cryptographically Weak Pseudo-Random Number Generator",
        description: "The application uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG is cryptographically weak."
    },
    759: {
        id: 759,
        name: "Use of a One-Way Hash without a Salt",
        description: "The application uses a one-way hash without a salt, making it vulnerable to rainbow table attacks."
    },
    
    // Race Conditions
    362: {
        id: 362,
        name: "Race Condition",
        description: "The application has multiple threads of execution and the order of operations can affect the correctness of the result."
    },
    366: {
        id: 366,
        name: "Race Condition within a Thread",
        description: "The application contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource."
    },
    367: {
        id: 367,
        name: "Time-of-check Time-of-use (TOCTOU) Race Condition",
        description: "The application checks the state of a resource before using it, but the resource's state can change between the check and the use."
    },
    
    // Resource Management
    400: {
        id: 400,
        name: "Uncontrolled Resource Consumption",
        description: "The application does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed."
    },
    415: {
        id: 415,
        name: "Double Free",
        description: "The application calls free() twice on the same memory address, potentially leading to memory corruption."
    },
    416: {
        id: 416,
        name: "Use After Free",
        description: "The application references memory after it has been freed, which can lead to program crashes or execution of arbitrary code."
    },
    476: {
        id: 476,
        name: "NULL Pointer Dereference",
        description: "The application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash."
    },
    590: {
        id: 590,
        name: "Free of Memory not on the Heap",
        description: "The application calls free() on a pointer to memory that was not allocated on the heap."
    },
    680: {
        id: 680, 
        name: "Integer Overflow to Buffer Overflow",
        description: "The application performs a calculation to determine how much memory to allocate, but an integer overflow can lead to allocating less memory than expected."
    },
    761: {
        id: 761,
        name: "Free of Pointer not at Start of Buffer",
        description: "The application calls free() on a pointer that was not returned from malloc() or similar allocation functions."
    },
    787: {
        id: 787,
        name: "Out-of-bounds Write",
        description: "The application writes data past the end, or before the beginning, of the intended buffer."
    },
    
    // Loop Issues
    835: {
        id: 835,
        name: "Loop with Unreachable Exit Condition",
        description: "The application contains a loop with an exit condition that cannot be reached, i.e., an infinite loop."
    },
    
    // Integer Issues
    190: {
        id: 190,
        name: "Integer Overflow or Wraparound",
        description: "The application performs a calculation that can produce an integer overflow or wraparound, when the resulting value is used in a security-critical context."
    },
    191: {
        id: 191,
        name: "Integer Underflow",
        description: "The application subtracts a value from a numeric variable, but the result is less than the variable's minimum allowable value."
    }
};

// Export TOP_CWES based on the database for backward compatibility
export const TOP_CWES = Object.values(CWE_DATABASE);

// Mapping of security checks to relevant CWEs
export const securityCheckToCWE: { [key: string]: number[] } = {
    'BufferOverflowCheck': [120, 119, 125, 787], // Buffer Copy without Checking Size, Improper Restriction of Operations within Bounds, Out-of-bounds Read, Out-of-bounds Write
    'HeapOverflowCheck': [122, 590, 761], // Heap-based Buffer Overflow, Free of Memory not on the Heap, Free of Pointer not at Start of Buffer
    'PlaintextPasswordCheck': [256, 319], // Plaintext Storage of a Password, Cleartext Transmission of Sensitive Information
    'RaceConditionCheck': [362, 366, 367], // Race Condition, Race Condition within a Thread, Time-of-check Time-of-use Race Condition
    'OtherVulnerabilitiesCheck': [78, 89, 94, 22], // OS Command Injection, SQL Injection, Code Injection, Path Traversal
    'RandomNumberGenerationCheck': [330, 338], // Use of Insufficiently Random Values, Use of Cryptographically Weak PRNG
    'WeakHashingEncryptionCheck': [327, 328, 759], // Use of a Broken/Risky Cryptographic Algorithm, Reversible One-Way Hash, Use of a One-Way Hash without a Salt
    'InfiniteLoopCheck': [400, 835], // Uncontrolled Resource Consumption, Loop with Unreachable Exit Condition
    'IntegerFlowCheck': [190, 191, 680], // Integer Overflow/Wraparound, Integer Underflow, Integer Overflow to Buffer Overflow
    'PathTraversalCheck': [22, 23, 36, 73], // Path Traversal, Relative Path Traversal, Absolute Path Traversal, External Control of File Name
    'FloatingInMemoryCheck': [416, 415, 476] // Use After Free, Double Free, NULL Pointer Dereference
};

// Helper function to get CWE objects for a security check
export function getCWEsForSecurityCheck(checkName: string): CWE[] {
    const cweIds = securityCheckToCWE[checkName] || [];
    return cweIds.map(id => CWE_DATABASE[id]).filter(cwe => cwe !== undefined);
}

// Single, unified mapping of CVEs to security checks
export const CVE_MAPPING: { [key: string]: { id: string; description: string; cvss: number; severity: string }[] } = {
    'BufferOverflowCheck': [
      {
        id: "CVE-2021-3156",
        description: "Heap-based buffer overflow in Sudo's pwfeedback option allows privilege escalation.",
        cvss: 7.8,
        severity: "High"
      },
      {
        id: "CVE-2021-22986",
        description: "Buffer overflow in F5 BIG-IP iControl REST interface allows remote code execution.",
        cvss: 9.8,
        severity: "Critical"
      }
    ],
    'HeapOverflowCheck': [
      {
        id: "CVE-2021-4214",
        description: "Heap overflow in libpng's pngimage.c allows attackers to execute arbitrary code.",
        cvss: 7.8,
        severity: "High"
      },
      {
        id: "CVE-2020-6551",
        description: "Use-after-free in WebXR in Google Chrome prior to 84.0.4147.125 allows remote attackers to exploit heap corruption.",
        cvss: 8.8,
        severity: "High"
      }
    ],
    'PlaintextPasswordCheck': [
      {
        id: "CVE-2024-3082",
        description: "Plaintext storage of administrative password allows attackers with physical access to retrieve credentials.",
        cvss: 6.8,
        severity: "Medium"
      },
      {
        id: "CVE-2018-10822",
        description: "D-Link routers store administrative passwords in plaintext, accessible via directory traversal.",
        cvss: 8.8,
        severity: "High"
      }
    ],
    'RaceConditionCheck': [
      {
        id: "CVE-2021-1122",
        description: "NULL pointer dereference in NVIDIA vGPU Manager may lead to denial of service.",
        cvss: 5.5,
        severity: "Medium"
      },
      {
        id: "CVE-2017-5555",
        description: "TOCTOU vulnerability in file handling allows attackers to manipulate privileged operations.",
        cvss: 7.0,
        severity: "High"
      }
    ],
    'OtherVulnerabilitiesCheck': [
      {
        id: "CVE-2021-3344",
        description: "Privilege escalation in OpenShift builder allows users to overwrite container images.",
        cvss: 7.8,
        severity: "High"
      },
      {
        id: "CVE-2020-20915",
        description: "SQL injection vulnerability in PublicCMS v4.0 allows remote code execution.",
        cvss: 9.8,
        severity: "Critical"
      }
    ],
    'RandomNumberGenerationCheck': [
      {
        id: "CVE-2024-57835",
        description: "Use of cryptographically weak pseudo-random number generator in TANIGUCHI product.",
        cvss: 5.9,
        severity: "Medium"
      },
      {
        id: "CVE-2019-1212",
        description: "Memory corruption in Windows DHCP service when processing crafted packets.",
        cvss: 7.5,
        severity: "High"
      }
    ],
    'WeakHashingEncryptionCheck': [
      {
        id: "CVE-2023-0452",
        description: "Econolite EOS uses MD5 for encrypting privileged user credentials.",
        cvss: 7.5,
        severity: "High"
      },
      {
        id: "CVE-2018-4932",
        description: "Use-after-free vulnerability in Adobe Flash Player allows arbitrary code execution.",
        cvss: 9.8,
        severity: "Critical"
      }
    ],
    'InfiniteLoopCheck': [
      {
        id: "CVE-2022-0778",
        description: "Infinite loop in OpenSSL when parsing invalid certificates can lead to denial of service.",
        cvss: 7.5,
        severity: "High"
      },
      {
        id: "CVE-2021-46828",
        description: "Loop with unreachable exit condition in certain software configurations.",
        cvss: 5.5,
        severity: "Medium"
      }
    ],
    'IntegerFlowCheck': [
      {
        id: "CVE-2021-22986",
        description: "Integer overflow in F5 BIG-IP iControl REST interface allows remote code execution.",
        cvss: 9.8,
        severity: "Critical"
      },
      {
        id: "CVE-2019-1212",
        description: "Memory corruption in Windows DHCP service due to integer underflow.",
        cvss: 7.5,
        severity: "High"
      }
    ],
    'PathTraversalCheck': [
      {
        id: "CVE-2018-10822",
        description: "Directory traversal in D-Link routers allows unauthorized file access.",
        cvss: 8.8,
        severity: "High"
      },
      {
        id: "CVE-2018-3311",
        description: "Directory traversal in file upload functionality allows attackers to access sensitive files.",
        cvss: 7.5,
        severity: "High"
      }
    ],
    'FloatingInMemoryCheck': [
      {
        id: "CVE-2020-6551",
        description: "Use-after-free in WebXR in Google Chrome allows remote attackers to exploit heap corruption.",
        cvss: 8.8,
        severity: "High"
      },
      {
        id: "CVE-2020-0674",
        description: "Use-after-free vulnerability in Microsoft Internet Explorer 11 allows arbitrary code execution.",
        cvss: 7.5,
        severity: "High"
      }
    ]
  };
  

// Enhanced mapping with prioritization logic to reduce redundancy

// Helper function to prioritize and deduplicate CWEs for a security check
export function prioritizeCWEs(checkName: string, detectedIssues: string[] = []): number[] {
    // Get the full list of CWEs for this check
    const allCWEs = securityCheckToCWE[checkName] || [];
    
    // If no issues were detected or we don't have specific prioritization logic
    // for this check, return the full list
    if (detectedIssues.length === 0 || !checkSpecificPrioritization[checkName]) {
      return allCWEs;
    }
    
    // Apply check-specific prioritization logic
    return checkSpecificPrioritization[checkName](detectedIssues, allCWEs);
  }
  
  // Type for prioritization functions
  type PrioritizationFunction = (issues: string[], allCWEs: number[]) => number[];
  
  // Check-specific prioritization logic
  const checkSpecificPrioritization: { [key: string]: PrioritizationFunction } = {
    // For cryptographic issues
    'WeakHashingEncryptionCheck': (issues, allCWEs) => {
      const prioritizedCWEs = new Set<number>();
      let hasMD5 = false;
      let hasSHA1 = false;
      let hasNoSalt = false;
      
      // Analyze issues to determine what specific vulnerabilities are present
      issues.forEach(issue => {
        if (issue.includes('MD5') || issue.includes('md5')) {
          hasMD5 = true;
        }
        if (issue.includes('SHA1') || issue.includes('sha1')) {
          hasSHA1 = true;
        }
        if (issue.includes('without a salt') || issue.includes('no salt')) {
          hasNoSalt = true;
        }
      });
      
      // Add specific weak algorithm CWE if MD5 or SHA1 is detected
      if (hasMD5 || hasSHA1) {
        prioritizedCWEs.add(327); // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
      } else if (allCWEs.includes(328)) {
        // Only add generic weak hash if no specific algorithm was identified
        prioritizedCWEs.add(328); // CWE-328: Use of Weak Hash
      }
      
      // Add salt-related CWE if detected
      if (hasNoSalt) {
        prioritizedCWEs.add(759); // CWE-759: Use of a One-Way Hash without a Salt
      }
      
      return Array.from(prioritizedCWEs);
    },
    
    // For buffer overflow issues
    'BufferOverflowCheck': (issues, allCWEs) => {
      const prioritizedCWEs = new Set<number>();
      let hasReadIssue = false;
      let hasWriteIssue = false;
      let hasSizeIssue = false;
      
      // Analyze issues to determine what specific vulnerabilities are present
      issues.forEach(issue => {
        if (issue.includes('read') || issue.includes('Read')) {
          hasReadIssue = true;
        }
        if (issue.includes('write') || issue.includes('Write')) {
          hasWriteIssue = true;
        }
        if (issue.includes('size') || issue.includes('Size') || 
            issue.includes('strcpy') || issue.includes('strcat')) {
          hasSizeIssue = true;
        }
      });
      
      // Prioritize specific CWEs based on issue details
      if (hasSizeIssue) {
        prioritizedCWEs.add(120); // CWE-120: Buffer Copy without Checking Size of Input
      }
      if (hasReadIssue) {
        prioritizedCWEs.add(125); // CWE-125: Out-of-bounds Read
      }
      if (hasWriteIssue) {
        prioritizedCWEs.add(787); // CWE-787: Out-of-bounds Write
      }
      
      // Only add generic buffer issue CWE if we don't have more specific ones
      if (prioritizedCWEs.size === 0 && allCWEs.includes(119)) {
        prioritizedCWEs.add(119); // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
      }
      
      return Array.from(prioritizedCWEs);
    },
    
    // For race condition issues
    'RaceConditionCheck': (issues, allCWEs) => {
      const prioritizedCWEs = new Set<number>();
      let hasTOCTOU = false;
      let hasThreadIssue = false;
      
      // Analyze issues to determine what specific vulnerabilities are present
      issues.forEach(issue => {
        if (issue.includes('TOCTOU') || issue.includes('time-of-check') || 
            issue.includes('time of check')) {
          hasTOCTOU = true;
        }
        if (issue.includes('thread') || issue.includes('concurrent')) {
          hasThreadIssue = true;
        }
      });
      
      // Prioritize specific CWEs based on issue details
      if (hasTOCTOU) {
        prioritizedCWEs.add(367); // CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
      } else if (hasThreadIssue) {
        prioritizedCWEs.add(366); // CWE-366: Race Condition within a Thread
      } else if (allCWEs.includes(362)) {
        prioritizedCWEs.add(362); // CWE-362: Race Condition
      }
      
      return Array.from(prioritizedCWEs);
    },
    
    // For memory management issues
    'HeapOverflowCheck': (issues, allCWEs) => {
      const prioritizedCWEs = new Set<number>();
      let hasUseAfterFree = false;
      let hasDoubleFree = false;
      let hasNullPointer = false;
      
      // Analyze issues to determine what specific vulnerabilities are present
      issues.forEach(issue => {
        if (issue.includes('use after free') || issue.includes('Use after free')) {
          hasUseAfterFree = true;
        }
        if (issue.includes('double free') || issue.includes('Double free')) {
          hasDoubleFree = true;
        }
        if (issue.includes('NULL') || issue.includes('null') || 
            issue.includes('uninitialized')) {
          hasNullPointer = true;
        }
      });
      
      // Add specific CWEs based on detected issues
      if (hasUseAfterFree) {
        prioritizedCWEs.add(416); // CWE-416: Use After Free
      }
      if (hasDoubleFree) {
        prioritizedCWEs.add(415); // CWE-415: Double Free
      }
      if (hasNullPointer) {
        prioritizedCWEs.add(476); // CWE-476: NULL Pointer Dereference
      }
      
      // If none of the specific issues were found, include all CWEs for this check
      if (prioritizedCWEs.size === 0) {
        allCWEs.forEach(cwe => prioritizedCWEs.add(cwe));
      }
      
      return Array.from(prioritizedCWEs);
    },
    
    // For path traversal issues
    'PathTraversalCheck': (issues, allCWEs) => {
      const prioritizedCWEs = new Set<number>();
      let hasRelativePath = false;
      let hasAbsolutePath = false;
      let hasExternalControl = false;
      
      // Analyze issues to determine what specific vulnerabilities are present
      issues.forEach(issue => {
        if (issue.includes('relative path') || issue.includes('../')) {
          hasRelativePath = true;
        }
        if (issue.includes('absolute path') || issue.includes('/')) {
          hasAbsolutePath = true;
        }
        if (issue.includes('user input') || issue.includes('external')) {
          hasExternalControl = true;
        }
      });
      
      // Prioritize specific CWEs based on issue details
      if (hasRelativePath) {
        prioritizedCWEs.add(23); // CWE-23: Relative Path Traversal
      } else if (hasAbsolutePath) {
        prioritizedCWEs.add(36); // CWE-36: Absolute Path Traversal
      } else {
        prioritizedCWEs.add(22); // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
      }
      
      if (hasExternalControl) {
        prioritizedCWEs.add(73); // CWE-73: External Control of File Name or Path
      }
      
      return Array.from(prioritizedCWEs);
    },


    'RandomNumberGenerationCheck': (issues, allCWEs) => {
  const prioritizedCWEs = new Set<number>();
  let hasInsecureRNG = false;
  let hasWeakSeed = false;
  
  issues.forEach(issue => {
    if (issue.includes('rand') || issue.includes('random')) {
      hasInsecureRNG = true;
    }
    if (issue.includes('seed') || issue.includes('time(NULL)')) {
      hasWeakSeed = true;
    }
  });
  
  if (hasWeakSeed) {
    prioritizedCWEs.add(330); // Use of Insufficiently Random Values
  } else if (hasInsecureRNG) {
    prioritizedCWEs.add(338); // Use of Cryptographically Weak PRNG
  }
  
  return prioritizedCWEs.size > 0 ? Array.from(prioritizedCWEs) : [allCWEs[0]];
},

'IntegerFlowCheck': (issues, allCWEs) => {
  const prioritizedCWEs = new Set<number>();
  let hasOverflow = false;
  let hasUnderflow = false;
  let hasBufferRelated = false;
  
  issues.forEach(issue => {
    if (issue.includes('overflow')) {
      hasOverflow = true;
    }
    if (issue.includes('underflow')) {
      hasUnderflow = true;
    }
    if (issue.includes('buffer') || issue.includes('allocation')) {
      hasBufferRelated = true;
    }
  });
  
  if (hasOverflow) {
    prioritizedCWEs.add(190); // Integer Overflow or Wraparound
  }
  if (hasUnderflow) {
    prioritizedCWEs.add(191); // Integer Underflow
  }
  if (hasBufferRelated && hasOverflow) {
    prioritizedCWEs.add(680); // Integer Overflow to Buffer Overflow
  }
  
  return prioritizedCWEs.size > 0 ? Array.from(prioritizedCWEs) : [allCWEs[0]];
},

'PlaintextPasswordCheck': (issues, allCWEs) => {
  const prioritizedCWEs = new Set<number>();
  let hasStorage = false;
  let hasTransmission = false;
  
  issues.forEach(issue => {
    if (issue.includes('storage') || issue.includes('stored')) {
      hasStorage = true;
    }
    if (issue.includes('transmission') || issue.includes('transmitted')) {
      hasTransmission = true;
    }
  });
  
  if (hasStorage) {
    prioritizedCWEs.add(256); // Plaintext Storage of a Password
  }
  if (hasTransmission) {
    prioritizedCWEs.add(319); // Cleartext Transmission of Sensitive Information
  }
  
  return prioritizedCWEs.size > 0 ? Array.from(prioritizedCWEs) : [256]; // Default to storage
},

'InfiniteLoopCheck': (issues, allCWEs) => {
  const prioritizedCWEs = new Set<number>();
  let hasResourceConsumption = false;
  let hasInfiniteLoop = false;
  
  issues.forEach(issue => {
    if (issue.includes('resource') || issue.includes('memory') || issue.includes('consumption')) {
      hasResourceConsumption = true;
    }
    if (issue.includes('infinite') || issue.includes('unreachable exit')) {
      hasInfiniteLoop = true;
    }
  });
  
  if (hasResourceConsumption) {
    prioritizedCWEs.add(400); // Uncontrolled Resource Consumption
  }
  if (hasInfiniteLoop) {
    prioritizedCWEs.add(835); // Loop with Unreachable Exit Condition
  }
  
  return prioritizedCWEs.size > 0 ? Array.from(prioritizedCWEs) : [835]; // Default to infinite loop
},

'FloatingInMemoryCheck': (issues, allCWEs) => {
  const prioritizedCWEs = new Set<number>();
  let hasUseAfterFree = false;
  let hasDoubleFree = false;
  let hasNullPointer = false;
  
  issues.forEach(issue => {
    if (issue.includes('use after free') || issue.includes('use-after-free')) {
      hasUseAfterFree = true;
    }
    if (issue.includes('double free')) {
      hasDoubleFree = true;
    }
    if (issue.includes('NULL pointer') || issue.includes('null pointer')) {
      hasNullPointer = true;
    }
  });
  
  if (hasUseAfterFree) {
    prioritizedCWEs.add(416); // Use After Free
  }
  if (hasDoubleFree) {
    prioritizedCWEs.add(415); // Double Free
  }
  if (hasNullPointer) {
    prioritizedCWEs.add(476); // NULL Pointer Dereference
  }
  
  return prioritizedCWEs.size > 0 ? Array.from(prioritizedCWEs) : [416]; // Default to use after free
    },
    
    // For injection issues
    'OtherVulnerabilitiesCheck': (issues, allCWEs) => {
      const prioritizedCWEs = new Set<number>();
      let hasCommandInjection = false;
      let hasSQLInjection = false;
      let hasCodeInjection = false;
      
      // Analyze issues to determine what specific vulnerabilities are present
      issues.forEach(issue => {
        if (issue.includes('command injection') || issue.includes('OS command')) {
          hasCommandInjection = true;
        }
        if (issue.includes('SQL injection') || issue.includes('SQL command')) {
          hasSQLInjection = true;
        }
        if (issue.includes('code injection') || issue.includes('code generation')) {
          hasCodeInjection = true;
        }
      });
      
      // Add specific CWEs based on detected issues
      if (hasCommandInjection) {
        prioritizedCWEs.add(78); // CWE-78: Improper Neutralization of Special Elements used in an OS Command
      }
      if (hasSQLInjection) {
        prioritizedCWEs.add(89); // CWE-89: Improper Neutralization of Special Elements used in an SQL Command
      }
      if (hasCodeInjection) {
        prioritizedCWEs.add(94); // CWE-94: Improper Control of Generation of Code
      }
      
      // If none of the specific issues were found, include all CWEs for this check
      if (prioritizedCWEs.size === 0) {
        allCWEs.forEach(cwe => prioritizedCWEs.add(cwe));
      }
      
      return Array.from(prioritizedCWEs);
    }
  };
  
  /**
   * This function should be used in the cTester.ts file to prioritize CWEs
   * before updating the security analysis provider.
   */
  export function getCWEsForIssues(checkName: string, issues: string[]): number[] {
    // Get prioritized CWEs or fall back to all CWEs
    return prioritizeCWEs(checkName, issues);
  }


  













export class SecurityAnalysisProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | void> = this._onDidChangeTreeData.event;

    private securityIssues: vscode.TreeItem[] = [];
    private matchedCWEs: vscode.TreeItem[] = [];
    private rawIssuesText: string[] = []; // Store raw issue text for sharing
    private isAnalyzing: boolean = false;
    private cveItems: vscode.TreeItem[] = [];

    constructor(private generatedCodeProvider: GeneratedCodeProvider) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    clear(): void {
        this.securityIssues = [];
        this.matchedCWEs = [];
        this.rawIssuesText = [];
        this.cveItems = [];
        this.refresh();
    }

    /**
     * Updates the security analysis results with matched issues, CWEs, and CVEs.
     */
    updateSecurityAnalysis(
        issues: string[],
        cveDetails: { id: string; description: string }[] = [],
        matchedCWEs: CWE[] = (() => {
            const cweSet = new Set<number>();
            const issuesByCheck: { [checkName: string]: string[] } = {};
        
            // Group issues by the check name (parsed from the message)
            for (const issue of issues) {
                const match = issue.match(/\(([A-Za-z]+Check)\)$/);
                const checkName = match ? match[1] : 'UnknownCheck';
                if (!issuesByCheck[checkName]) {
                    issuesByCheck[checkName] = [];
                }
                issuesByCheck[checkName].push(issue);
            }
        
            // Prioritize and collect CWEs per check
            for (const [checkName, checkIssues] of Object.entries(issuesByCheck)) {
                const prioritized = getCWEsForIssues(checkName, checkIssues);
                prioritized.forEach(cweId => cweSet.add(cweId));
            }
        
            return Array.from(cweSet)
                .map(id => CWE_DATABASE[id])
                .filter(cwe => cwe !== undefined);
        })(),
        
    ): void {
        // Store raw issues for sharing with the right panel
        this.rawIssuesText = [...issues];

        // Format security issues
        this.securityIssues = issues.map(issue => {
            // Remove the check name if present (e.g., "Message (CheckName)")
            const formattedIssue = issue.replace(/\s+\([A-Za-z]+Check\)$/, '');
            
            const item = new vscode.TreeItem(formattedIssue);
            item.iconPath = new vscode.ThemeIcon("warning");
            item.tooltip = `Security issue detected: ${issue}`;
            item.description = 'Click to copy';
            item.command = {
                command: 'extension.copyToClipboard',
                title: 'Copy Code',
                arguments: [issue],
            };
            return item;
        });

        // Format CWE details
        this.matchedCWEs = matchedCWEs.map(cwe => {
            const item = new vscode.TreeItem(
                `CWE-${cwe.id}: ${cwe.name}`,
                vscode.TreeItemCollapsibleState.None
            );
            item.tooltip = cwe.description;
            
            // Truncate long descriptions for display
            let description = cwe.description;
            if (description.length > 80) {
                description = description.substring(0, 77) + '...';
            }
            item.description = description;
            
            item.iconPath = new vscode.ThemeIcon("alert");
            return item;
        });

        // Update CVE assignments
        this.updateCveAssignments(cveDetails);
        this.refresh();
        this.isAnalyzing = false;
    }

    private updateCveAssignments(cveDetails: { id: string; description: string }[]): void {
        this.cveItems = cveDetails.map(cve => {
            const item = new vscode.TreeItem(
                `${cve.id}`,
                vscode.TreeItemCollapsibleState.None
            );
            
            item.tooltip = `${cve.id}: ${cve.description}`;
            
            // Truncate long descriptions for display
            let description = cve.description;
            if (description.length > 80) {
                description = description.substring(0, 77) + '...';
            }
            item.description = description;
            
            return item;
        });
    }

    async analyzeLatestGeneratedCode(): Promise<void> {
        const code = this.generatedCodeProvider.getLatestGeneratedCode();

        if (code) {
            this.isAnalyzing = true;
            this.clear();
            runCTests(code, this);
        } else {
            vscode.window.showWarningMessage("No code generated to analyze.");
        }
    }

    async analyzeCode(code: string): Promise<void> {
        if (code) {
            this.isAnalyzing = true;
            this.clear();
            runCTests(code, this);
        } else {
            vscode.window.showWarningMessage("No code provided to analyze.");
        }
    }

    /**
     * Get raw security issues text for external components
     */
    getRawSecurityIssues(): string[] {
        return this.rawIssuesText;
    }

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: vscode.TreeItem): vscode.ProviderResult<vscode.TreeItem[]> {
        if (!element) {
            return [
                new vscode.TreeItem('Security Issues', vscode.TreeItemCollapsibleState.Expanded),
                new vscode.TreeItem('CWE Details', vscode.TreeItemCollapsibleState.Expanded),
                new vscode.TreeItem('CVE Assignments', vscode.TreeItemCollapsibleState.Expanded),
            ];
        }

        if (element.label === 'Security Issues') {
            if (this.isAnalyzing) {
                const analyzingItem = new vscode.TreeItem("Analyzing code...");
                analyzingItem.iconPath = new vscode.ThemeIcon("loading~spin");
                return [analyzingItem];
            } else if (this.securityIssues.length > 0) {
                return this.securityIssues;
            } else {
                return [new vscode.TreeItem("No security issues found!")];
            }
        }

        if (element.label === 'CWE Details') {
            if (this.isAnalyzing) {
                const analyzingItem = new vscode.TreeItem("Analyzing code...");
                analyzingItem.iconPath = new vscode.ThemeIcon("loading~spin");
                return [analyzingItem];
            } else if (this.matchedCWEs.length > 0) {
                return this.matchedCWEs;
            } else {
                return [new vscode.TreeItem("No matching CWEs found.")];
            }
        }

        if (element.label === 'CVE Assignments') {
            if (this.cveItems.length > 0) {
                return this.cveItems;
            } else {
                return [new vscode.TreeItem("No CVEs found.")];
            }
        }

        return [];
    }
}