/**
 * Railway entry point for Fleetify Backend
 * Directs to the actual server in src/server
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 Starting Fleetify Backend for Railway deployment...');

// Change to server directory and start the actual server
process.chdir(join(__dirname, 'src/server'));

const serverProcess = spawn('npm', ['start'], {
  stdio: 'inherit',
  env: process.env,
  shell: true
});

serverProcess.on('error', (error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});

serverProcess.on('close', (code) => {
  console.log(`Server process exited with code ${code}`);
  process.exit(code);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  serverProcess.kill('SIGTERM');
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  serverProcess.kill('SIGINT');
});