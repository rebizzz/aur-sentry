# Disposable Container Sandbox & Honey-Tokens

AUR Sentry includes a containerized runtime sandbox (`sandbox/`) for dynamically building and auditing packages in a disposable environment.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |           Host Orchestrator           |
                      |          (sandbox/run.sh)             |
                      +---------------------------------------+
                                    |              |
                    read-only /src  |              | telemetry (fd 3)
                                    v              v
                       +------------------------------------+
                       |     Rootless Container Sandbox     |
                       |    (podman or docker execution)    |
                       |                                    |
                       |  - Unprivileged `builder` user     |
                       |  - Root-owned strace monitoring    |
                       |  - Decoy canary secret traps       |
                       +------------------------------------+
```

---

## 1. Honey-Tokens & Canary Traps

Every build and installation pass plants realistic decoy secrets inside the container:

- **SSH Keys:** `~/.ssh/id_fake`
- **AWS Credentials:** `~/.aws/credentials`
- **Docker Credentials:** `~/.docker/config.json`
- **Environment Secrets:** `~/.env` with decoy database strings and webhook tokens
- **Google Cloud Auth:** `~/.config/gcloud/application_default_credentials.json`

If any scriptlet attempts to read or exfiltrate these files, the host-captured `strace` telemetry flags it instantly as `MALICIOUS`.

---

## 2. Resource Quotas & Isolation

Containers are executed with strict constraints:
- **Memory Cap:** `--memory=4g`
- **CPU Quota:** `--cpus=2`
- **Process Limits:** `--pids-limit=4096`
- **Privilege Separation:** Root `strace` traces the unprivileged `builder` user so code cannot detach or kill the monitor.
- **Engine Support:** Automatically runs on `podman` or `docker`.
