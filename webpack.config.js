const nodeExternals = require('webpack-node-externals');
const webpack = require('webpack');

module.exports = {
  target: 'node',
  entry: './dukpt.js',
  module: {
    rules: [
      { test: /\.js$/, use: 'babel-loader' },
    ]
  },
  output: {
    filename: 'dukpt.js',
  },
  externals: [nodeExternals()],
  plugins: [
    new webpack.BannerPlugin({ banner: "#!/usr/bin/env node", raw: true }),
  ],
}
