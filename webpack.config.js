// @ts-check

'use strict';

const path = require('path');
const webpack = require('webpack');
const dotenv = require('dotenv');

dotenv.config();

/** @typedef {import('webpack').Configuration} WebpackConfig **/

/** @type WebpackConfig */
const extensionConfig = {
  target: 'node',
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',

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
  // Add optimization to prevent data from being stripped in production
  optimization: {
    minimize: false, // Prevents aggressive minimization that might remove your data
    usedExports: true
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.AMPLITUDE_API_KEY': JSON.stringify(process.env.AMPLITUDE_API_KEY),
      'process.env.DEEPSEEK_API_KEY': JSON.stringify(process.env.DEEPSEEK_API_KEY),
    }),
    // Prevent chunk splitting to keep all your code in one bundle
    new webpack.optimize.LimitChunkCountPlugin({
      maxChunks: 1
    })
  ],
  devtool: 'nosources-source-map',
  infrastructureLogging: {
    level: 'log',
  },
};

module.exports = [extensionConfig];