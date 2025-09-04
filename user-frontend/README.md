# user-frontend

React + Vite + Tailwind frontend for the user-service (Spring Boot) backend.

## Prerequisites
- Node.js LTS
- user-service running at `http://localhost:8080`

## Setup
1. Install dependencies:
```bash
npm install
```
2. Create `.env` and set API base URL:
```bash
echo "VITE_API_BASE_URL=http://localhost:8080" > .env
```

## Run
```bash
npm run dev
```

Open `http://localhost:5173`.

## Key Pages
- `/` Home (links to flows)
- `/register`, `/login`
- `/verify?token=...&autoLogin=true|false`
- `/forgot-password`, `/reset-password?token=...`
- `/complete-oauth?regToken=...&email=...&preUsername=...`
- `/link-oauth?linkToken=...`
- `/me` (protected)

## Notes
- API base URL comes from `VITE_API_BASE_URL`.
- JWT is stored in localStorage as `auth_token`.
- 401/403 handled by axios interceptor (redirect to `/login`, with login endpoint exempted).
