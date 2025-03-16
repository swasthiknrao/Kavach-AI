const fs = require('fs');
const path = require('path');
const archiver = require('archiver');

// Create output directory if it doesn't exist
const outputDir = path.resolve(__dirname, '../dist');
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// Create a file to stream archive data to
const output = fs.createWriteStream(path.join(outputDir, 'kavach-ai-security.zip'));
const archive = archiver('zip', {
  zlib: { level: 9 } // Sets the compression level
});

// Listen for all archive data to be written
output.on('close', function() {
  console.log(`Package created successfully: ${archive.pointer()} total bytes`);
  console.log('The package is ready in the dist folder.');
});

// Handle warnings and errors
archive.on('warning', function(err) {
  if (err.code === 'ENOENT') {
    console.warn(err);
  } else {
    throw err;
  }
});

archive.on('error', function(err) {
  throw err;
});

// Pipe archive data to the file
archive.pipe(output);

// Get the build directory
const buildDir = path.resolve(__dirname, '../dist');

// Add files from the build directory
archive.directory(buildDir, false);

// Finalize the archive
archive.finalize();

console.log('Creating package...'); 