const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { Pool } = require("pg");
require("dotenv").config();

const sqlitePath = path.join(__dirname, "..", "data", "forum.db");
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL. Add it to .env before running migration.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === "false" ? false : { rejectUnauthorized: false }
});

function getSqliteRows() {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(sqlitePath, sqlite3.OPEN_READONLY, (openErr) => {
      if (openErr) {
        reject(openErr);
      }
    });

    db.all(
      `SELECT student_name, student_school, student_phone, parent_phone, course, discover_source, created_at
       FROM registrations
       ORDER BY id ASC`,
      [],
      (err, rows) => {
        db.close();
        if (err) {
          reject(err);
          return;
        }
        resolve(rows || []);
      }
    );
  });
}

async function ensureTable() {
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
}

async function migrate() {
  await ensureTable();
  const rows = await getSqliteRows();
  if (!rows.length) {
    console.log("No rows found in SQLite. Nothing to migrate.");
    return;
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const row of rows) {
      await client.query(
        `INSERT INTO registrations
          (student_name, student_school, student_phone, parent_phone, course, discover_source, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          row.student_name,
          row.student_school,
          row.student_phone,
          row.parent_phone,
          row.course,
          row.discover_source,
          row.created_at
        ]
      );
    }
    await client.query("COMMIT");
    console.log(`Migrated ${rows.length} registration(s) from SQLite to PostgreSQL.`);
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

migrate()
  .catch((error) => {
    console.error("Migration failed:", error.message);
    process.exit(1);
  })
  .finally(async () => {
    await pool.end();
  });
