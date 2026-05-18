# Zero-Downtime Deployment via `handoff-supervisor`

`beyond-auth` supports zero-downtime binary swaps when run under a [`beyond-handoff`](https://crates.io/crates/beyond-handoff)-compatible supervisor process. The supervisor binds the listening TCP socket once, holds it across child process generations, and drives the handoff protocol to swap the running `beyond-auth` binary with no dropped connections.

See [`ARCHITECTURE.md`](../ARCHITECTURE.md#zero-downtime-handoff) for what this does at the protocol level. This document is for operators wiring it into a real deployment.

## Process model

```
handoff-supervisor (PID 1)                    ← long-lived parent
        │
        │ binds listener on :443 (or whatever)
        │
        │ exec's, passing LISTEN_FDS=1, LISTEN_FDNAMES=http
        ▼
beyond-auth serve --data-dir /var/lib/beyond-auth   ← child, swappable
        │
        │ accepts on inherited fd 3
        ▼
clients
```

The supervisor never proxies traffic — clients connect directly to the inherited socket. The supervisor's only runtime job is to drive handoffs when triggered.

## Prerequisites

1. The `handoff-supervisor` binary, built from the [`beyond-handoff`](https://github.com/beyondoss/handoff) repo. Not crates.io-published; embedders are expected to either use the reference binary directly or link the `beyond-handoff` library into their own supervisor.
2. A persistent directory for the handoff lock + control socket (default `/var/lib/beyond-auth`; configurable via `BEYOND_DATA_DIR`). Must be writable by the user running `beyond-auth`.
3. The usual `beyond-auth` requirements: Postgres reachable, `SIGNING_KEY_ENCRYPTION_KEY` + `ADMIN_SECRET` + `DATABASE_URL` set.

## Supervisor config

The reference supervisor reads a TOML config. Minimal example:

```toml
# /etc/beyond-auth/handoff.toml
binary = "/usr/local/bin/beyond-auth"
args = ["serve"]
env = [
  ["DATABASE_URL", "postgres://auth:…@db.internal/auth"],
  ["SIGNING_KEY_ENCRYPTION_KEY", "…"],
  ["ADMIN_SECRET", "…"],
  ["BEYOND_DATA_DIR", "/var/lib/beyond-auth"],
  ["LOG_LEVEL", "info"],
]
control_socket = "/var/lib/beyond-auth/.handoff.sock"
trigger_socket = "/var/run/beyond-auth/trigger.sock"
journal = "/var/lib/beyond-auth/.handoff.journal"
drain_grace_secs = 60
deadline_secs = 120

[[listeners]]
name = "http"
addr = "0.0.0.0:443"
```

### Tuning the timeouts

- `drain_grace_secs`: wall-clock cap on the drain phase. Should comfortably exceed `p99(drain)` for your traffic. Drain consists of "stop accepting + wait for in-flight HTTP requests to finish." For auth — Argon2-bound, no streaming endpoints — `p99` is typically a few hundred milliseconds. Default 60s is generous.
- `deadline_secs`: overall handoff cap (drain + seal + spawn successor + wait for Ready). Should be `drain_grace_secs + p99(cold-start) + 30s`. Cold start dominated by `db::migrate` (a no-op when schema matches) and signing-key decrypt. Default 120s is comfortable.

The handoff library emits heartbeat frames every ~2s during long drain hooks, so the supervisor's per-recv liveness timeout (10s) does not trip on slow drains; only the configured `drain_grace_secs` does.

## systemd unit

```ini
# /etc/systemd/system/beyond-auth.service
[Unit]
Description=Beyond Auth (handoff-supervised)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/handoff-supervisor --config /etc/beyond-auth/handoff.toml
Restart=on-failure
RestartSec=2s

# Required: a stable directory for the flock + control socket, owned by the
# service user. The supervisor + child both write here.
StateDirectory=beyond-auth
StateDirectoryMode=0750
RuntimeDirectory=beyond-auth
RuntimeDirectoryMode=0750

# Service user
User=beyond-auth
Group=beyond-auth

# Sandboxing (optional but recommended)
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Note: do **not** set `KillMode=process` — the default (`control-group`) is correct because the supervisor + child form a single cgroup; SIGTERM on the unit cleanly stops both.

## Triggering a handoff

Connect to the supervisor's `trigger_socket` and send `handoff\n`:

```bash
# Swap to a freshly-deployed binary at the path configured in handoff.toml.
echo handoff | nc -U /var/run/beyond-auth/trigger.sock

# Override the binary path inline (e.g. to swap to a new version that
# was just unpacked at /opt/beyond-auth/v0.2.0/beyond-auth).
echo "handoff /opt/beyond-auth/v0.2.0/beyond-auth" | nc -U /var/run/beyond-auth/trigger.sock
```

The supervisor replies with `ok handoff_id=… committed=true abort_reason=None` on success or `ok … committed=false abort_reason=Some("…")` on a clean abort. On a commit, the supervisor begins accepting future trigger commands against the new child; the old binary's process has already exited.

## Rolling deploys

For a standard rolling deploy:

1. Unpack the new `beyond-auth` binary at a versioned path.
2. (Optional) Run `beyond-auth migrate` against the database from the new binary if the deploy includes schema changes — handoff does not run migrations during the swap.
3. Trigger a handoff with the new binary path.
4. Verify with a smoke request (`/livez`, `/v1/jwks.json`).

If you operate the rolling deploy via a `systemd` template per node and an orchestrator (Ansible, k8s, etc.), the trigger step is one shell line per node. The supervisor itself is _not_ restarted — it stays running across deploys.

## Rollback

If a deploy went wrong and the new binary is misbehaving, drive another handoff with the previous binary's path:

```bash
echo "handoff /opt/beyond-auth/v0.1.9/beyond-auth" | nc -U /var/run/beyond-auth/trigger.sock
```

This is a normal handoff in the other direction. The supervisor does not distinguish "forward" vs "back" — every handoff is just "swap to this binary."

To stop entirely:

```bash
systemctl stop beyond-auth
```

The supervisor exits, sending SIGTERM to the current child. The child drains via the standard signal path (the `handoff_bridge` accept loop's `signal_fut` arm fires), waits for in-flight requests up to a 30s grace window, then exits.

## Kubernetes

The supervisor runs as PID 1 in the pod. The deployment looks like a normal long-running service:

```yaml
spec:
  template:
    spec:
      containers:
        - name: beyond-auth
          image: ghcr.io/yourorg/beyond-auth:latest
          command: ["/usr/local/bin/handoff-supervisor"]
          args: ["--config", "/etc/beyond-auth/handoff.toml"]
          volumeMounts:
            - name: data
              mountPath: /var/lib/beyond-auth
            - name: trigger
              mountPath: /var/run/beyond-auth
          ports:
            - containerPort: 443
              name: https
          # Liveness and readiness hit the inherited port — same as if
          # the binary were the entrypoint.
          livenessProbe:
            httpGet:
              path: /livez
              port: https
              scheme: HTTPS
          readinessProbe:
            httpGet:
              path: /readyz
              port: https
              scheme: HTTPS
      volumes:
        - name: data
          # PersistentVolumeClaim or emptyDir — needs to survive across
          # handoffs within a pod, but not across pod restarts.
          emptyDir: {}
        - name: trigger
          emptyDir: {}
```

Note: in-pod handoffs are useful for slow-burning state in the supervisor (journal, lock), but standard k8s deploys replace the whole pod — at which point Kubernetes' rolling update with `maxSurge=1` gives you the same zero-downtime guarantee at the pod boundary, and you don't need the handoff layer at all. Use handoffs in k8s for high-traffic deployments where waiting for full pod scheduling cycles between rollouts is too slow, or for sidecar architectures where the pod has expensive per-node state.

## Observability

- **Supervisor stderr**: text logs from `handoff-supervisor`. Pipe to your log aggregator.
- **Child stderr**: structured JSON from `beyond-auth`. Inherits the supervisor's stdio.
- **Prometheus**: `beyond-auth` exposes `/metrics` on the inherited listener. Handoff state is observable indirectly via the existing `http_connections_active` and `http_requests_total` gauges — during a handoff you'll see `http_connections_active` drain to zero, then climb back up as the successor accepts.
- **Handoff journal**: `/var/lib/beyond-auth/.handoff.journal` exists only during an in-progress handoff. If it persists across a supervisor restart, the next supervisor recovers from it on startup (logs `resumed from prior handoff journal`).

## Troubleshooting

| Symptom                                                  | Diagnosis                                                                                                                                                                     |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BEYOND_DATA_DIR: lock held by pid N`                    | Another `beyond-auth` is running on the same data dir. Stop the other process or pick a different `BEYOND_DATA_DIR`.                                                          |
| Trigger returns `committed=false abort_reason=Some("…")` | Successor failed to come up. Check child stderr for the actual error. Common: misconfigured `DATABASE_URL`, missing extension `.so`, expired KEK.                             |
| Trigger returns `Timeout("Drained")`                     | Drain phase exceeded `drain_grace_secs`. Check for long-running HTTP requests (slow upstream OAuth flow, hung database). Bump `drain_grace_secs` or fix the slow handler.     |
| `/livez` 200 from old binary even after `committed=true` | The supervisor is reporting the swap before the old process has fully exited (the supervisor reaps best-effort). A few seconds is normal; if it persists, check process tree. |
| Supervisor crashes mid-handoff                           | Incumbent self-recovers via `resume_after_abort`; no data loss. Restart the supervisor; the journal file on disk recovers the in-flight state.                                |
| Both old and new processes alive after `committed=true`  | The new process holds the flock. The old process is exiting; OS will reap it within seconds. Don't trigger another handoff until the old process is gone.                     |
