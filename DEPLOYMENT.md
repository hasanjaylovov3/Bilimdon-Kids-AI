# Deployment: Render + Neon

This project serves its frontend and API from the same Express origin. Deploying them together keeps the existing same-origin API calls and HttpOnly session cookie behavior intact.

## 1. Create the Neon database

1. Create a PostgreSQL project in Neon.
2. Copy the pooled connection string (or the connection string Neon recommends for application runtime).
3. Keep the connection string private. Do not commit it to GitHub.

## 2. Deploy the Render web service

1. In Render, create a new Blueprint deployment and select this GitHub repository.
2. Select branch `feature/integrate-legacy-kids-ui` while the pull request is still under review.
3. Render reads `render.yaml` and creates the Node web service.
4. In the service Environment settings, set:
   - `DATABASE_URL`: the Neon connection string
   - `GEMINI_API_KEY`: the Google Gemini API key
5. Keep `NODE_ENV=production`, `GEMINI_MODEL=gemini-2.5-flash`, and `SESSION_DAYS=14` as defined by the Blueprint.
6. Deploy/redeploy after setting the secrets.

The Render service serves both `public/` and `/api/*` from one HTTPS origin. Do not set a separate frontend API URL unless the architecture is deliberately changed.

## 3. Initialize the database

Open the Neon SQL Editor and run the complete contents of `db/schema.sql` once. This creates the parent, child, session, learning progress, and AI conversation tables.

## 4. Verify

Open `https://<your-render-service>.onrender.com/api/health`. Expected response after setup:

- `ok: true`
- `database: "ok"`
- `gemini: true`

Then open the service root URL and test parent registration, login, an AI tutor request, and saving/viewing learning progress.

## Important notes

- Never put `DATABASE_URL` or `GEMINI_API_KEY` in source code, frontend files, commits, or chat messages.
- The Render free web service may sleep after inactivity and can take time to wake up.
- The Neon database is external to Render. Keep its project and connection string active.
- This guide does not configure an Android APK. Capacitor/API origin setup is a separate step.
- This Blueprint is intentionally configured for the feature branch. Do not deploy or merge the pull request to `main` until the app has been tested and approved.
