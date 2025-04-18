// @ts-check

'use strict';

const path = require('path');
const webpack = require('webpack'); // Added to inject environment variables
const dotenv = require('dotenv'); // To load .env file

dotenv.config(); // Automatically loads environment variables from .env file

/** @typedef {import('webpack').Configuration} WebpackConfig **/

/** @type WebpackConfig */
const extensionConfig = {
  target: 'node',
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development', // Dynamic mode based on environment

  entry: './src/extension.ts',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'extension.js',
    libraryTarget: 'commonjs2',
  },
  externals: {
    vscode: 'commonjs vscode',
    'tree-sitter': 'commonjs tree-sitter',
    'tree-sitter-c': 'commonjs tree-sitter-c',
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: [{ loader: 'ts-loader' }],
      },
    ],
  },
  plugins: [
    new webpack.DefinePlugin({
      // Inject the AMPLITUDE_API_KEY environment variable into the bundle
      'process.env.AMPLITUDE_API_KEY': JSON.stringify(process.env.AMPLITUDE_API_KEY),
    }),
  ],
  devtool: 'nosources-source-map',
  infrastructureLogging: {
    level: 'log',
  },
};

module.exports = [extensionConfig];
