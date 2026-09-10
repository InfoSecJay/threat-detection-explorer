# Detection Explorer -- project rules

Project-specific rules; they override the global CLAUDE.md where the two
differ (Jay's decision, 2026-09-10).

## Git and deploys

- Commit directly to `master`. Railway (API + sync worker) and Vercel
  (frontend) deploy from every push to master; there is no staging branch
  and Jay does not review pull requests for this repo. Do not create
  branches or PRs unless Jay asks for one.
- Conventional Commits (`type(scope): subject`), one intent per commit,
  files added by name.
- Only `backend/**` changes redeploy Railway (watch patterns); a backend
  push during the nightly sync (02:00-02:15 America/Toronto) restarts the
  worker and the sync lease requeues the job. Avoid that window.

## Verification before "done"

- Backend: `cd backend; venv\Scripts\python.exe -m pytest tests -q`
  (the venv is the project interpreter; ~1,500 tests, ~20 s).
- Frontend: `cd frontend; npm run build; npm run lint; npx vitest run`.
  Capture each exit code; eslint runs with `--max-warnings 0`.
- Anything that changes normalization lands in the data only at the next
  nightly sync. Verify on prod after that sync, then close the issue.
- Prod probes go through the public API with curl (Cloudflare blocks
  Python urllib's user agent). The data-source and event-type filters are
  `data_sources_normalized` and `event_categories` until #139 lands;
  unknown params are silently ignored.
- Read-only prod Postgres: `railway run --service Postgres -- <absolute
  path to backend\venv\Scripts\python.exe> <script.py>` with asyncpg on
  `DATABASE_PUBLIC_URL`. `railway ssh ... psql` does not work from here.

## Work tracking

- Priorities live in GitHub Issues (`priority:now|next|later`, `area:*`,
  `type:*`); there is no roadmap file. Umbrella issues carry checkbox
  sub-tasks and a pickup note as their last comment.
- Reference docs live in `docs/` (schema, taxonomy, performance, audits).
