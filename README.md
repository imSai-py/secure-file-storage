# Secure File Storage System

A full-stack secure file storage system built with React (frontend) and Node.js/Express (backend), featuring AES-256-GCM envelope encryption.

## Prerequisites

- **Node.js**: >= 20.x
- **PostgreSQL**: Running locally or remotely
- **Redis**: Running locally or remotely
- **AWS S3**: An S3 bucket with valid access credentials

## Installation & Setup

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd secure-file-storage
```

### 2. Install dependencies

This project uses a root `package.json` to manage dependencies for both the frontend and backend.

```bash
npm run install:all
```

### 3. Environment Configuration

1. Copy the example environment variables file to a new `.env` file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and fill in the required credentials:
   - **PostgreSQL**: Set `DB_PASSWORD` (and other variables if not using default localhost).
   - **Redis**: Set `REDIS_PASSWORD` if applicable.
   - **AWS S3**: Fill in your AWS access keys and S3 bucket name.
   - **JWT**: Update the secret keys with secure random strings.

Note: There are also individual `.env.example` files in the `backend` and `frontend` directories if you wish to run them completely separated.

### 4. Database Setup

Run the database migrations to set up the necessary tables:

```bash
cd backend
npm run db:migrate
cd ..
```

### 5. Running the Application

You can start both the frontend and backend concurrently from the root directory:

```bash
npm run dev
```

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000

## Project Structure

- `/backend` - Node.js + Express API (TypeScript)
- `/frontend` - React Application (Vite)
- `/` - Root workspace configuration

## Scripts

From the root directory:
- `npm run install:all` - Installs dependencies for root, frontend, and backend
- `npm run dev` - Starts both frontend and backend development servers
- `npm run dev:frontend` - Starts only the frontend dev server
- `npm run dev:backend` - Starts only the backend dev server

## Important Security Note

**Never commit your `.env` file!** It is already included in the `.gitignore`.
