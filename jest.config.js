module.exports = {
  testEnvironment: 'jsdom',
  moduleFileExtensions: ['js', 'json'],
  transform: {
    '^.+\\.js$': 'babel-jest'
  },
  testMatch: [
    '**/tests/**/*.test.js',
    '**/src/**/*.test.js'
  ],
  collectCoverage: true,
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/**/*.test.js',
    '!**/node_modules/**'
  ],
  coverageReporters: ['text', 'lcov'],
  setupFilesAfterEnv: ['./tests/setup.js']
}; 