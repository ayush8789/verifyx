# VerifyX - Job/Internship Verifier (Hackathon MVP)

Local run:
1. Backend:
   cd backend
   npm install
   node db.js
   node server.js

2. Frontend:
   cd frontend
   npm install
   npm start

Docker:
cd infra
docker-compose up --build

Repo layout:
- backend/ : Node.js + Express + SQLite
- frontend/: React SPA
- infra/: docker-compose (optional)
