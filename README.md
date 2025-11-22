# FleetifyApp Backend API

Express.js API server for FleetifyApp fleet management system.

## 🚀 Features

- **Secure Authentication**: JWT-based auth with role-based access control
- **Rate Limiting**: Request throttling and abuse prevention
- **API Documentation**: Auto-generated Swagger/OpenAPI docs
- **Caching**: Redis-based intelligent caching
- **Monitoring**: Comprehensive logging and error tracking
- **Security**: Helmet, CORS, input validation

## 📦 Deployment

### Railway (Recommended)

```bash
# Install Railway CLI
npm i -g railway

# Login and link project
railway login
railway link

# Deploy
railway up
```

### Manual Deployment

```bash
# Install dependencies
npm install

# Build
npm run build

# Start production server
npm start
```

## 🌐 API Documentation

Once deployed, visit `/api-docs` for interactive API documentation.

## 🔧 Environment Variables

See `.env.example` for required environment variables.

## 📊 Health Check

- **Endpoint**: `/health`
- **Method**: GET
- **Response**: JSON with server status and timestamp