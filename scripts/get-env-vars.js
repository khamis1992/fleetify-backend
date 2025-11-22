/**
 * Helper script to identify required environment variables for Railway deployment
 */

console.log('🚀 FleetifyApp Backend - Railway Environment Variables\n');
console.log('📋 Required Environment Variables for Railway:\n');

console.log('SUPABASE_URL=https://your-project-id.supabase.co');
console.log('SUPABASE_ANON_KEY=your_supabase_anon_key');
console.log('SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key');
console.log('JWT_SECRET=your_jwt_secret_minimum_32_characters');
console.log('NODE_ENV=production');
console.log('FRONTEND_URL=https://fleetifyapp-8qhenz069-khamis-1992-hotmailcoms-projects.vercel.app\n');

console.log('🔍 Where to find these values:');
console.log('1. SUPABASE_URL & KEYS: Go to https://supabase.com/dashboard');
console.log('   - Select your FleetifyApp project');
console.log('   - Settings → API');
console.log('   - Copy Project URL, anon public key, and service_role key');
console.log('\n2. JWT_SECRET: Generate a secure 32+ character string');
console.log('   You can use: openssl rand -base64 32\n');

console.log('🌐 Optional Variables:');
console.log('PORT=3001 (Railway sets this automatically)');
console.log('API_BASE_URL=https://your-app-name.up.railway.app\n');

console.log('✅ Copy these into Railway → Settings → Variables');
console.log('🚀 Then click "Deploy Now" in Railway!');