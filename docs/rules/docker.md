# Docker rules (`DOC-*`) — weight 1.0×

A project with no Docker configuration scores 10/10 here — absence isn't a defect.

## Dockerfile

| ID | Severity | What it detects |
|---|---|---|
| `DOC-001` | high | Dockerfile present but no `.dockerignore` — `COPY . .` may bundle secrets and `node_modules`. |
| `DOC-010` | high | Container runs as root (no `USER` directive). |
| `DOC-011` | medium | No multi-stage build. |
| `DOC-012` | medium | `:latest` or untagged base image. |
| `DOC-013` | low | No `HEALTHCHECK`. |
| `DOC-014` | medium | `COPY . .` copies the entire build context. |
| `DOC-015` | low | `apt-get install` without cache cleanup. |

## docker-compose

| ID | Severity | What it detects |
|---|---|---|
| `DOC-020` | critical | `privileged: true`. |
| `DOC-021` | high | Hardcoded credential in a compose `environment` block. |
| `DOC-022` | low | No restart policy. |
| `DOC-023` | low | No resource limits. |
| `DOC-024` | medium | Port bound on all interfaces (`0.0.0.0` or bare port mapping) — once per **service**, named; the per-file penalty is capped at 2.0 (N published dev services are one convention missing, not N failures). |
| `DOC-025` | critical | `/var/run/docker.sock` mounted into a service (short or long volume syntax). The Docker API over that socket is root on the host; `:ro` does not help. |

## False-positive notes

- **`DOC-021` understands secret mounts.** Values that are paths to mounted secrets
  (`./secrets/…`, `/run/secrets/…`) are not credentials.
- `DOC-024` is about *general* services; an MCP/agent server on `0.0.0.0` is the more severe
  `AGT-005`.
- **`DOC-025` only counts a real mount** — a commented-out line, another unix socket
  (`mysqld.sock`), or `DOCKER_HOST=unix:///var/run/docker.sock` in an env value do not fire.
  Reverse proxies, dashboards and CI runners that genuinely need the socket are still
  flagged: the fix is a socket proxy exposing only the calls they need, and the decision
  belongs in a justified suppression, not in silence. Found in the field on a production
  compose that PRISM had passed clean.
- **`DOC-025` knows what a socket proxy is.** A service whose image or name says
  `socket-proxy` / `docker-proxy` (tecnativa/docker-socket-proxy and friends) is the
  recommended pattern itself: it fires at **low** with its own title and asks you to verify
  the allowlist (`CONTAINERS=1`, `EXEC=0`, ...) and that only the intended services reach it.
  Found in the field on a framework with five correctly allowlisted proxies that was getting
  five criticals for doing the right thing.
