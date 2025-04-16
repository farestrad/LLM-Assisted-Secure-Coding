//@ts-check
'use strict';

const path = require('path');

//@ts-check
/** @typedef {import('webpack').Configuration} WebpackConfig **/

/** @type WebpackConfig */
const extensionConfig = {
  target: 'node', // VS Code extensions run in a Node.js-context
  mode: 'none', // this leaves the source code as close as possible to the original (when packaging we set this to 'production')
  entry: './src/extension.ts', // the entry point of this extension
  output: {
    // the bundle is stored in the 'dist' folder (check package.json)
    path: path.resolve(__dirname, 'dist'),
    filename: 'extension.js',
    libraryTarget: 'commonjs2'
  },
  externals: {
    vscode: 'commonjs vscode' // Only exclude VS Code API
    // Removed tree-sitter and tree-sitter-c from externals to ensure they get bundled
  },
  resolve: {
    // Support reading TypeScript and JavaScript files
    extensions: ['.ts', '.js'],
    // Add fallbacks for node modules that might cause issues
    fallback: {
      "path": require.resolve("path-browserify"),
      "fs": false,
      "os": require.resolve("os-browserify/browser"),
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer/")
    }
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'ts-loader'
          }
        ]
      },
      // Add rule for binary modules that might need special handling
      {
        test: /\.node$/,
        use: 'node-loader'
      }
    ]
  },
  plugins: [
    // Add any necessary webpack plugins here
  ],
  devtool: 'nosources-source-map',
  infrastructureLogging: {
    level: "log", // Enables logging required for problem matchers
  },
  // Ensure native modules work correctly across platforms
  node: {
    __dirname: false,
    __filename: false
  }
};

module.exports = [extensionConfig];