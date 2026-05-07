# RouteHawk Labs

The local demo lab will contain a safe vulnerable API and a small frontend with embedded API routes.

Run the lightweight lab directly:

```powershell
py labs/demo_server.py
```

Or run it with Docker:

```powershell
cd labs
docker compose up --build
```

Then scan it from another terminal:

```powershell
py -m routehawk scan --config config.local-lab.yaml --out report.html
```

Demo routes:

- `GET /api/users/1/profile`
- `GET /api/users/1/billing`
- `GET /api/orders/1001`
- `POST /api/admin/users/1/role`
- `GET /internal/metrics`
- `GET /debug/config`
- `GET /swagger.json`
- `POST /graphql`
