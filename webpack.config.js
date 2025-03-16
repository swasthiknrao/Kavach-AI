const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const ZipPlugin = require('zip-webpack-plugin');
const fs = require('fs');

module.exports = (env, argv) => {
  const isProduction = argv.mode === 'production';
  
  // Create models directory if it doesn't exist
  const modelsDir = path.resolve(__dirname, 'dist', 'models');
  if (!fs.existsSync(modelsDir)) {
    fs.mkdirSync(modelsDir, { recursive: true });
  }
  
  return {
    entry: {
      popup: './src/popup/popup.js',
      background: './src/background/background.js',
      content: './src/content/content.js',
      tf: './src/popup/tf.js'
    },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name]/[name].js',
      clean: true
    },
    module: {
      rules: [
        {
          test: /\.js$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: ['@babel/preset-env']
            }
          }
        },
        {
          test: /\.css$/,
          use: ['style-loader', 'css-loader']
        },
        {
          test: /\.(png|svg|jpg|jpeg|gif)$/i,
          type: 'asset/resource',
          generator: {
            filename: 'assets/[name][ext]'
          }
        }
      ]
    },
    plugins: [
      new HtmlWebpackPlugin({
        template: './src/popup/popup.html',
        filename: 'popup/popup.html',
        chunks: ['popup', 'tf']
      }),
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: '' },
          { from: 'assets', to: 'assets' }
        ]
      }),
      ...(isProduction ? [
        new ZipPlugin({
          filename: 'kavach-ai-security.zip',
          path: path.resolve(__dirname, 'dist')
        })
      ] : [])
    ],
    devtool: isProduction ? false : 'source-map'
  };
}; 