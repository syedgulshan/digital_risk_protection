# BrandShield AI — Deployment Guide (Vercel Frontend + Render Backend)

This guide explains how to deploy **BrandShield AI** with:
1. **Frontend:** React + Vite deployed to **Vercel**
2. **Backend:** Python Flask API + Machine Learning models deployed to **Render**
3. **Single Public URL:** Seamless routing where all `/api/*` requests route to Render while users interact with one unified domain.

---

## Architecture Overview

```
┌──────────────────────────────────────────────┐
│  Vercel (Frontend — React + Vite)            │
│  Domain: https://your-brandshield.vercel.app │
├──────────────────────────────────────────────┤
│  • Single Public URL for users               │
│  • Digital Guardian Universe theme           │
│  • 3D Holographic Threat Globe Canvas        │
│  • AI Guardian Mascot with eye-tracking      │
│  • 4-Slide Onboarding Tour                   │
│  • vercel.json rewrites:                     │
│    /api/*  ──>  Render Backend               │
│    /health ──>  Render Backend               │
└──────────────────────┬───────────────────────┘
                       │ Proxied HTTPS Calls
                       ▼
┌──────────────────────────────────────────────┐
│  Render (Backend — Flask + Gunicorn)         │
│  Domain: https://brandshield-api.onrender.com│
├──────────────────────────────────────────────┤
│  • REST API endpoints (/api/auth, /api/scan) │
│  • Machine Learning Classifiers (3 models)   │
│  • VirusTotal API v3 & Gemini Explainer      │
│  • Supabase PostgreSQL & SQLite cache        │
│  • CORS with credentials enabled             │
└──────────────────────────────────────────────┘
```

---

## 1. Deploying the Backend to Render

### Prerequisites
- A free [Render account](https://render.com).
- Push this repository to GitHub or GitLab.

### Option A: Using the Render Blueprint (`render.yaml`) — Recommended
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** $\rightarrow$ **Blueprint**.
3. Select your repository. Render will automatically read [`render.yaml`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/render.yaml).
4. Fill in the required environment variables:
   - `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (optional, heuristic engine works offline)
   - `GEMINI_API_KEY`: Your Gemini API key (optional)
   - `SUPABASE_URL`: Your Supabase project URL
   - `SUPABASE_KEY`: Your Supabase service role / anon key
5. Click **Apply**. Render will automatically build with `pip install -r requirements.txt` and start with Gunicorn:
   ```bash
   gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
   ```
6. Copy your Render web service URL (e.g., `https://brandshield-api.onrender.com`).

### Option B: Manual Web Service Setup on Render
- **Name:** `brandshield-api`
- **Runtime:** `Python 3`
- **Build Command:** `pip install --upgrade pip && pip install -r requirements.txt`
- **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
- **Health Check Path:** `/health`
- **Environment Variables:**
  - `PYTHON_VERSION`: `3.12.0`
  - `FLASK_ENV`: `production`
  - `RENDER`: `true`
  - `FLASK_SECRET_KEY`: `(generate secure random string)`
  - `SUPABASE_URL`: `...`
  - `SUPABASE_KEY`: `...`
  - `VIRUSTOTAL_API_KEY`: `...`
  - `GEMINI_API_KEY`: `...`

---

## 2. Deploying the Frontend to Vercel

### Prerequisites
- A free [Vercel account](https://vercel.com).
- Your Render backend URL from Step 1.

### Option A: Deploying via Vercel Dashboard
1. Go to [Vercel Dashboard](https://vercel.com/dashboard) and click **Add New...** $\rightarrow$ **Project**.
2. Import your GitHub repository.
3. Configure Project Settings:
   - **Framework Preset:** `Vite`
   - **Root Directory:** Edit $\rightarrow$ select `frontend` (or leave as root; root [`vercel.json`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/vercel.json) handles building `frontend`).
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. In **Environment Variables**, add:
   - `VITE_API_BASE_URL`: `https://brandshield-api.onrender.com` (replace with your actual Render URL).
5. Click **Deploy**.

### Option B: Single URL Proxy via `vercel.json` (No Cross-Origin Needed!)
[`frontend/vercel.json`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/frontend/vercel.json) includes automatic reverse-proxy rewrites:
```json
{
  "framework": "vite",
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "https://brandshield-api.onrender.com/api/:path*"
    },
    {
      "source": "/health",
      "destination": "https://brandshield-api.onrender.com/health"
    },
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```
*Simply replace `https://brandshield-api.onrender.com` in `vercel.json` with your real Render URL before committing!*
When configured this way:
- Users access only `https://your-app.vercel.app`.
- All `/api/*` calls stay on the same origin and are routed by Vercel edge to Render.
- No third-party cookie blocking or CORS issues occur!

---

## 3. Local Development

To run both services locally:

### 1. Start the Flask Backend (Terminal 1)
```bash
python app.py
```
Backend runs on `http://127.0.0.1:5000`.

### 2. Start the Vite Frontend (Terminal 2)
```bash
npm run dev
# or: cd frontend && npm run dev
```
Frontend runs on `http://127.0.0.1:5173`.
Vite dev server proxies `/api` and `/health` requests automatically to `http://127.0.0.1:5000`.

---

## 4. Default Enterprise Credentials
- **Lead Analyst:** `analyst@brandshield.ai` / `CyberShield2026!`
- **Director of Cyber Defense:** `admin@brandshield.ai` / `CyberShield2026!`
- **Sign Up:** New analysts can self-enroll on the login page via **Sign Up**.
