const { Pool } = require("pg");
require("dotenv").config();

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL in environment.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS registrations (
      id SERIAL PRIMARY KEY,
      student_name TEXT NOT NULL,
      student_school TEXT NOT NULL,
      student_phone TEXT NOT NULL,
      parent_phone TEXT NOT NULL,
      course TEXT NOT NULL,
      discover_source TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_registrations_course_student_phone
    ON registrations (course, student_phone)
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS uq_registrations_course_parent_phone
    ON registrations (course, parent_phone)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS course_link_tokens (
      id SERIAL PRIMARY KEY,
      token_id TEXT NOT NULL UNIQUE,
      course_slug TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_course_link_tokens_token_id
    ON course_link_tokens (token_id)
  `);

  // Single-row table that overrides ADMIN_PASSWORD from .env at runtime
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_credentials (
      id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      password_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

module.exports = { pool, initDb };
