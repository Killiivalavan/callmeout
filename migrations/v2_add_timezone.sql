-- Add timezone column to users table for timezone-aware notifications
ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'UTC';
