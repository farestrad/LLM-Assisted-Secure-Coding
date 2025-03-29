# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-03-29

### Added
- **Getting Started Panel:** Introduced a dedicated panel to help new users get acquainted with SafeScript.
- **Code Improvement and Analysis Panel:** Added a new panel featuring a chat-like textbox for interactive code analysis and improvement. This panel supports both code analysis and code generation modes.
- **AI Suggestion History Integration:** Enabled direct addition of improved code suggestions into the AI Suggestion History from the analysis panel.
- **Toggle Mode Feature:** Implemented a toggle switch for users to easily switch between “Analyze & Improve” and “Generate Code” modes.
- **Enhanced Static Analysis Detection:** Integrated comprehensive static analysis enhancements, including CWE improvements, to more robustly detect security issues.

### Changed
- **Massive UI Overhaul:** Redesigned the user interface with updated color schemes, responsive layouts, and optimized user interactions for a modern look and feel.
- **Static Analysis Engine:** Upgraded and refined the underlying algorithms to enhance detection accuracy and overall performance.
- **API Integration:** Improved the extension’s performance by optimizing API calls for code analysis and generation, resulting in reduced latency.
- **Code Quality and Error Handling:** Refactored the codebase for better maintainability, added improved error handling mechanisms, and optimized performance.

### Fixed
- **Context Retention:** Resolved issues with webview context retention ensuring a smoother user experience when switching panels.
- **UI Bugs:** Fixed various interface glitches and inconsistencies across both analysis and generation modes.
- **Integration Glitches:** Addressed minor integration issues with the Code Llama service for more accurate vulnerability detection and code suggestions.

### Removed
- **Deprecated Features:** Eliminated outdated methods and obsolete UI components from previous releases to streamline the extension.

## [1.0.1] - 2025-02-07

### Added
- Integrated **Code Llama** for AI-powered code analysis.
- Introduced **method-level testing** to improve code quality insights.
- Added detection for **CVE** (Common Vulnerabilities and Exposures) to identify known security issues.
- Included detailed **CWE** (Common Weakness Enumeration) information to help address coding vulnerabilities.
- Implemented **better warning and error detection** for enhanced code quality analysis.

### Changed
- Upgraded the underlying AI algorithms to improve the accuracy of vulnerability detection.
- Refined user interface for displaying analysis results directly within the editor.

### Fixed
- Minor bug fixes to improve the overall performance of the extension.

### Removed
- Deprecated features related to older vulnerability detection methods.

## [0.0.1] - 2025-01-01

### Added
- Initial release of **SafeScript** extension for VS Code.
- Basic integration with **Code Llama** for basic code analysis and security checks.
- Initial error detection functionality.