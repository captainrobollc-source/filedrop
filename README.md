# Drop

A private place to pass files and text between your own devices (runs on Pocket).

- Upload by picking, dragging or pasting files; send text or links and copy them on another device.
- One password; each device signs in once and stays signed in. Changing it signs out every other device.
- Videos stream (range requests). HTML and other active files are always downloaded, never rendered.
- Refuses uploads that would leave less than 1 GB free.

No dependencies. Files and settings live in `data/` (persisted across Pocket deploys).

```bash
PORT=3000 node server.js
```

Environment (optional): `MAX_MB` (largest single file, default 4096).

## Deploying

Pushes to `main` deploy to the Pocket phone server automatically (it checks every 2 minutes), with a health check and automatic rollback if the new version fails to start.
