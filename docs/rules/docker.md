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
| `DOC-024` | medium | Port bound on all interfaces (`0.0.0.0` or bare port mapping). |

## False-positive notes

- **`DOC-021` understands secret mounts.** Values that are paths to mounted secrets
  (`./secrets/…`, `/run/secrets/…`) are not credentials.
- `DOC-024` is about *general* services; an MCP/agent server on `0.0.0.0` is the more severe
  `AGT-005`.
