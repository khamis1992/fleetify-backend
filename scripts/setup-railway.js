#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🚀 Railway Backend Setup Guide\n');
console.log('=====================================\n');

console.log('📋 Step 1: Get Your Supabase Credentials');
console.log('1. Go to: https://supabase.com/dashboard');
console.log('2. Select your FleetifyApp project');
console.log('3. Go to Settings → API');
console.log('4. Copy these values:\n');

console.log('🔑 Required Environment Variables:');
console.log('=====================================');
console.log('SUPABASE_URL=https://your-project-id.supabase.co');
console.log('SUPABASE_ANON_KEY=your_anon_key_here');
console.log('SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here');
console.log('JWT_SECRET=generate_32_character_secret');
console.log('FRONTEND_URL=https://fleetifyapp-8qhenz069-khamis-1992-hotmailcoms-projects.vercel.app');
console.log('NODE_ENV=production');
console.log('PORT=3000\n');

console.log('🛠️ Step 2: Railway Deployment');
console.log('=====================================');
console.log('1. Go to: https://railway.app');
console.log('2. Login with GitHub');
console.log('3. Click "New Project"');
console.log('4. Select "Upload Files"');
console.log(`5. Upload all files from: ${path.resolve(__dirname, '..')}`);
console.log('6. Go to Settings → Variables');
console.log('7. Add all environment variables from above');
console.log('8. Click "Deploy Now"\n');

console.log('✅ Step 3: Verify Deployment');
console.log('=====================================');
console.log('After deployment, test these URLs:');
console.log('- Health Check: https://your-app.up.railway.app/health');
console.log('- API Documentation: https://your-app.up.railway.app/api-docs\n');

console.log('🔗 Step 4: Connect Frontend to Backend');
console.log('=====================================');
console.log('1. Go to Vercel Dashboard → FleetifyApp Project');
console.log('2. Settings → Environment Variables');
console.log('3. Add: VITE_API_URL=https://your-railway-app.up.railway.app');
console.log('4. Vercel will automatically redeploy\n');

console.log('📊 Quick JWT Secret Generation:');
console.log('=====================================');
console.log('You can generate a JWT secret using:');
console.log('- Online: https://www.uuidgenerator.net/api/version1');
console.log('- Node: crypto.randomBytes(32).toString("base64")');
console.log('- Python: secrets.token_urlsafe(32)');
console.log('- Any 32+ character random string\n');

console.log('🎯 That\'s it! Your FleetifyApp will be fully deployed!');
console.log('Frontend: Vercel ✅ | Backend: Railway ⏳ | Database: Supabase ✅');