# Deployment Guide - Threat Detection Explorer

This guide walks you through deploying Threat Detection Explorer to production using **Railway** (backend) and **Vercel** (frontend).

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Vercel       │     │    Railway      │     │   PostgreSQL    │
│   (Frontend)    │────▶│   (Backend)     │────▶│   (Database)    │
│    React App    │     │   FastAPI API   │     │   on Railway    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**Estimated Cost**: Free tier should cover everything initially
- Vercel: Free for hobby projects
- Railway: $5/month credit (usually enough for small apps)

---

## Prerequisites

1. **GitHub Account** - Your code should be in a GitHub repository
2. **Railway Account** - Sign up at [railway.app](https://railway.app)
3. **Vercel Account** - Sign up at [vercel.com](https://vercel.com)

---

## Step 1: Deploy Backend to Railway

### 1.1 Create Railway Account & Project

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Find and select your `threat-detection-explorer` repository
5. Railway will ask which folder to deploy - select the `backend` folder

### 1.2 Add PostgreSQL Database

1. In your Railway project, click **"New"** → **"Database"** → **"Add PostgreSQL"**
2. Railway will automatically create a PostgreSQL database
3. Click on the PostgreSQL service to see connection details

### 1.3 Configure Environment Variables

1. Click on your backend service in Railway
2. Go to **"Variables"** tab
3. Add the following environment variables:

```
ENVIRONMENT=production
DATABASE_URL=${{Postgres.DATABASE_URL}}
FRONTEND_URL=https://your-app.vercel.app
ENABLE_SCHEDULER=true
SYNC_SCHEDULE_HOUR=2
SYNC_SCHEDULE_MINUTE=0
```

**Important**:
- `DATABASE_URL` uses Railway's variable reference syntax `${{Postgres.DATABASE_URL}}`
- Railway will automatically inject the correct PostgreSQL connection string
- The app automatically converts the URL to the correct async format
- Update `FRONTEND_URL` after deploying to Vercel (Step 2)

### 1.4 Configure Build Settings

1. Go to **"Settings"** tab
2. Set **Root Directory** to `backend`
3. Railway should auto-detect Python and use the settings from `railway.toml`

### 1.5 Deploy

1. Railway will automatically deploy when you push to your GitHub repo
2. Wait for the build to complete (first build may take 5-10 minutes)
3. Once deployed, click **"Generate Domain"** to get your backend URL
4. Your backend API will be available at: `https://your-backend.up.railway.app`

### 1.6 Verify Backend

Test your backend is working:
```bash
curl https://your-backend.up.railway.app/api/health
```

Should return: `{"status":"healthy","app":"Threat Detection Explorer"}`

---

## Step 2: Deploy Frontend to Vercel

### 2.1 Create Vercel Account & Project

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New..."** → **"Project"**
3. Import your `threat-detection-explorer` repository
4. Vercel will auto-detect it's a monorepo

### 2.2 Configure Project Settings

1. **Framework Preset**: Vite
2. **Root Directory**: `frontend`
3. **Build Command**: `npm run build`
4. **Output Directory**: `dist`

### 2.3 Configure Environment Variables

Add the following environment variable:

```
VITE_API_URL=https://your-backend.up.railway.app/api
```

Replace `your-backend.up.railway.app` with your actual Railway backend URL from Step 1.5.

### 2.4 Deploy

1. Click **"Deploy"**
2. Wait for the build to complete (usually 1-2 minutes)
3. Your frontend will be available at: `https://your-app.vercel.app`

---

## Step 3: Update Backend CORS

After deploying the frontend, update the backend's `FRONTEND_URL`:

1. Go to Railway → Your project → Backend service → Variables
2. Update `FRONTEND_URL` to your Vercel URL (e.g., `https://your-app.vercel.app`)
3. Railway will automatically redeploy

---

## Step 4: Initial Data Sync

The database will be empty initially. You need to sync the rule repositories:

### Option A: Wait for Scheduled Sync
The scheduler runs daily at 2 AM UTC by default. You can wait for the first automatic sync.

### Option B: Trigger Manual Sync
```bash
# Trigger sync for all repositories
curl -X POST https://your-backend.up.railway.app/api/scheduler/trigger \
  -H "Content-Type: application/json" \
  -d '{}'

# Check sync status
curl https://your-backend.up.railway.app/api/scheduler/jobs
```

**Note**: The first sync takes 10-30 minutes as it clones all repositories and processes thousands of rules.

---

## Step 5: Custom Domain (Optional)

### Vercel Custom Domain
1. Go to Vercel → Your project → Settings → Domains
2. Add your custom domain (e.g., `threatdetectionexplorer.com`)
3. Follow Vercel's DNS configuration instructions

### Railway Custom Domain
1. Go to Railway → Your project → Backend service → Settings
2. Click "Custom Domain"
3. Add your API subdomain (e.g., `api.threatdetectionexplorer.com`)
4. Follow Railway's DNS configuration instructions

### Update Environment Variables
If using custom domains, update:
- Backend `FRONTEND_URL` to your custom frontend domain
- Frontend `VITE_API_URL` to your custom backend domain

---

## Monitoring & Maintenance

### Check Sync Status
```bash
curl https://your-backend.up.railway.app/api/scheduler/status
```

### View Sync History
```bash
curl https://your-backend.up.railway.app/api/scheduler/jobs
```

### Trigger Manual Sync
```bash
curl -X POST https://your-backend.up.railway.app/api/scheduler/trigger \
  -H "Content-Type: application/json" \
  -d '{"repository": "sigma"}'  # Or omit for all repos
```

### View Logs
- **Railway**: Go to your service → "Logs" tab
- **Vercel**: Go to your project → "Deployments" → Click deployment → "Logs"

---

## Troubleshooting

### Backend won't start
- Check Railway logs for error messages
- Verify `DATABASE_URL` is set correctly
- Ensure PostgreSQL service is running

### Frontend can't connect to API
- Verify `VITE_API_URL` is set correctly in Vercel
- Check that backend CORS allows your frontend URL
- Test backend directly: `curl https://your-backend.up.railway.app/api/health`

### Sync fails
- Check Railway logs during sync
- Ensure the service has enough memory (upgrade if needed)
- Check disk space for cloned repositories

### Database connection errors
- Verify PostgreSQL service is running in Railway
- Check that `DATABASE_URL` uses the correct format:
  `postgresql+asyncpg://user:password@host:port/database`

---

## Cost Optimization

### Railway
- Free tier includes $5/month credit
- PostgreSQL uses some of this credit
- If you exceed the limit, consider:
  - Reducing sync frequency
  - Using a smaller database plan

### Vercel
- Free tier is generous for static sites
- No concerns for typical usage

---

## Updating the Application

### Automatic Deployments
Both Railway and Vercel will automatically redeploy when you push to your GitHub repository.

### Manual Deployments
- **Railway**: Go to service → Deployments → Click "Deploy"
- **Vercel**: Go to project → Deployments → Click "Redeploy"

---

## Security Checklist

- [ ] Environment variables are set (not hardcoded)
- [ ] `FRONTEND_URL` is set correctly for CORS
- [ ] Debug mode is disabled in production (`ENVIRONMENT=production`)
- [ ] Database credentials are not exposed
- [ ] HTTPS is enabled (automatic with Railway and Vercel)
