module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }], // Updated to follow ts-jest's new recommendation
  },
  extensionsToTreatAsEsm: ['.ts'], // Handle ESM correctly
  modulePathIgnorePatterns: ['<rootDir>/out/'], // Ignore build artifacts

  // ✅ Removed deprecated 'globals' & integrated into 'transform'
  collectCoverage: true,
  collectCoverageFrom: [
    'src/testers/c/**/*.{js,ts,jsx,tsx}', // Covers all JavaScript/TypeScript files inside the 'c' folder
  ],
  coverageReporters: ['html', 'text'], // Generate HTML & console reports
  coverageDirectory: '<rootDir>/coverage', // Coverage output directory

  // ✅ Added to prevent duplicate mock issues
  moduleNameMapper: {
    '^vscode$': '<rootDir>/src/test/__mocks__/vscode.ts', 
  },
};
