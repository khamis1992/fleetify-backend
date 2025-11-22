#!/bin/bash

# Fleetify Backend Deployment Script

set -e

echo "🚀 Deploying Fleetify Backend..."

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "Installing Railway CLI..."
    npm install -g railway
fi

# Login to Railway (interactive)
echo "🔐 Please login to Railway..."
railway login

# Link to existing project or create new one
echo "🔗 Linking to Railway project..."
railway link

# Set environment variables
echo "⚙️ Setting environment variables..."
railway variables set NODE_ENV=production
railway variables set PORT=3001

# Deploy
echo "📦 Deploying to Railway..."
railway up

# Get the deployed URL
echo "🌐 Getting deployment URL..."
RAILWAY_URL=$(railway domains --json | jq -r '.[0].domain' 2>/dev/null || echo "")
if [ -n "$RAILWAY_URL" ]; then
    echo "✅ Backend deployed successfully!"
    echo "🔗 URL: https://$RAILWAY_URL"
    echo "📚 API Docs: https://$RAILWAY_URL/api-docs"
    echo "🏥 Health Check: https://$RAILWAY_URL/health"
else
    echo "✅ Backend deployed! Check Railway dashboard for URL."
fi

echo "🎉 Deployment complete!"