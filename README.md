# TEAM-DOPICODE PS3

Attack surface mapper demo project.

## Python Runtime

Use Python `3.12.x` locally and on the VPS. The backend `Makefile` now defaults to `python3.12`, and a fresh install will fail fast if it is pointed at another interpreter.

## Backend Demo

```bash
cd /Users/atharva/WE NEED BAD BITCH VALIDATION/project
make install
make demo
```

If `python3.12` is not the default name on the machine, pass it explicitly:

```bash
make install PY=/path/to/python3.12
```

For a VPS deployment, expose the API explicitly:

```bash
make run HOST=0.0.0.0 PORT=8000
```

If a local port is already occupied while rehearsing, override it:

```bash
make demo PORT=8001
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## Build

```bash
cd frontend
npm run build
```
