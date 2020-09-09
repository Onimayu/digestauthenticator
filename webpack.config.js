const path = require("path");
const Webpack = require("webpack");

exports.default = {
  mode: 'production',
  entry: './index.js',
  target: 'node',
  output: {
    path: path.join(process.cwd(), 'build'),
    filename: 'index.js',
    libraryTarget: 'commonjs2'
  },
  externals: ['aws-sdk'],
  module: {
    rules: [
      {
        test: /\.js$/,
        enforce: 'pre',
        exclude: [/node_modules/]
      }
    ]
  },
  plugins: [
    new Webpack.optimize.OccurrenceOrderPlugin(),
    // new Webpack.DefinePlugin({
    // 	'process.env': {
    // 		NODE_ENV:	JSON.stringify('production')
    // 	}
    // }),
    new Webpack.LoaderOptionsPlugin({
      minimize: true,
      debug: false
    })
  ],
  devtool: 'inline-source-map',
  bail: true
};
