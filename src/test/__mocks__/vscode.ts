// src/test/__mocks__/vscode.ts
module.exports = {
    workspace: {
      getConfiguration: jest.fn(),
    },
    window: {
      showErrorMessage: jest.fn(),
    },
    // Add other mock methods if necessary
  };
  