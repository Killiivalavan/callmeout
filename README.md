# callMeOut

A simple, efficient, and annoying git push tracker.

## Overview

callMeOut is a web application designed to help developers stay consistent with their git pushes. It tracks your daily push activity and sends a "friendly" reminder via Discord if you haven't met your daily goal by a specific time.

## Key Features

- **GitHub Integration:** Seamlessly connect your GitHub account to track pushes.
- **Activity Heatmap:** Visualize your push history with a GitHub-style contribution graph.
- **Customizable Goals:** Set your own daily push target.
- **Discord Reminders:** Receive automated notifications when you're falling behind.
- **Timezone Aware:** Reminders are sent based on your local time.

## Tech Stack

- **Backend:** Node.js with Express
- **Database:** Supabase (PostgreSQL)
- **Frontend:** Plain HTML/CSS/JS (no frameworks)
- **Auth:** GitHub OAuth
- **Hosting:** Optimized for Vercel

## Project Structure

- `src/server.js`: Main Express application and API logic.
- `src/views/`: HTML templates for index, onboarding, and dashboard.
- `public/`: Static assets including the merged `styles/main.css` and client-side JS.
- `migrations/`: SQL files for database schema and updates.

## Setup

1. Clone the repository.
2. Install dependencies: `npm install`.
3. Configure environment variables (see `.env.example` if available).
4. Run locally: `npm start`.

---
*Stay consistent, or get called out.*
