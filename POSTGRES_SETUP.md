# PostgreSQL Migration Setup

The backend now uses PostgreSQL instead of `data/forum.db`.

## 1) Create `.env`

Copy `.env.example` to `.env` and set your real database URL:

```
PORT=3000
DATABASE_URL=postgresql://username:password@host:5432/database_name
DB_SSL=true
ADMIN_USERNAME=teacher
ADMIN_PASSWORD=change-this-password
ALLOWED_HOSTS=localhost,127.0.0.1
```

For local PostgreSQL, you can often set:

```
DB_SSL=false
```

## 2) Start server

```bash
npm start
```

On startup, the server auto-creates the `registrations` table if it does not exist.

## Optional: migrate old SQLite data

If you already collected student data in `data/forum.db`, run:

```bash
npm run migrate:db
```

This copies all rows from SQLite into PostgreSQL.

## 3) Links

- Student form: `/student`
- Teacher dashboard: `/teacher`

Both pages use the same PostgreSQL database, so data is synchronized automatically.

## Security Notes

- Teacher dashboard and admin API are protected with HTTP Basic Auth using:
  - `ADMIN_USERNAME`
  - `ADMIN_PASSWORD`
- Set a strong `ADMIN_PASSWORD` before production.
- Configure `ALLOWED_HOSTS` with your real production domain.
