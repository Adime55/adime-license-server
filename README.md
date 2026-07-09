# Adime License Server

Minimal license validation server for Adime.

## Endpoints

- `GET /health`
- `POST /validate`
- `GET /admin/licenses`
- `POST /admin/licenses`
- `PATCH /admin/licenses/:license`

## Environment Variables

- `ADMIN_TOKEN`: admin API token. Keep this secret in Render environment variables.
- `PORT`: provided by Render automatically.
