# DEPLOY — landed (agent-receipts v0)

Deploy on a small Linux box (any distro with systemd). The service is a
single stdlib-only Python 3.8+ file. Nothing is deployed by the build agent;
this recipe is for the operator.

## 1. Dedicated unprivileged user

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin receipts
sudo mkdir -p /home/receipts/service /home/receipts/data
sudo cp receipts.py /home/receipts/service/
sudo chown -R receipts:receipts /home/receipts
sudo chmod 700 /home/receipts/data
```

`receipts` owns only `/home/receipts`. It has no read access to any other
user's data (default Linux home perms 750/700 apply). Do NOT add it to
privileged groups; do NOT grant sudo.

## 2. systemd system unit (loopback only)

`/etc/systemd/system/receipts.service`:

```ini
[Unit]
Description=agent-receipts v0 (read-after-write receipts)
After=network.target

[Service]
Type=simple
User=receipts
Group=receipts
WorkingDirectory=/home/receipts/service
Environment=AGENTRECEIPTS_DATA_DIR=/home/receipts/data
ExecStart=/usr/bin/python3 /home/receipts/service/receipts.py --host 127.0.0.1 --port 2587
Restart=on-failure
RestartSec=2

# hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/home/receipts/data
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now receipts.service
curl -s http://127.0.0.1:2587/   # smoke test: docs page
```

The socket is bound to 127.0.0.1 only; it is reachable from outside solely
via the tunnel below.

## 3. Public hostname via cloudflared (FOUNDER steps, ~10 min)

Do this in the Cloudflare dashboard + one CLI box; requires owning a domain
on Cloudflare.

1. Cloudflare dashboard -> Zero Trust -> Networks -> Tunnels -> **Create a
   tunnel** -> choose "Cloudflared" connector type -> name it `agentreceipts`.
2. Note the tunnel token the dashboard shows.
3. On the server, install cloudflared, then run the connector:
   `sudo cloudflared service install <TUNNEL_TOKEN>` (installs a systemd
   service that maintains the tunnel).
4. Back in the dashboard, add a **Public Hostname** to the tunnel:
   - subdomain: `landed` (your domain), path: leave empty
   - service type: `HTTP`, URL: `localhost:2587`
5. Test: `curl -s https://landed.wirt.ee/` returns the docs page.
6. (Recommended) Under the hostname's settings, enable Cloudflare's
   rate-limiting rule as a second abuse layer in front of the built-in
   60/hour/agent limit.

## 4. Recovery: wipe and regenerate the signing key

If the key leaks (or you want a clean identity), all existing signatures
become unverifiable — that is the point. To reset:

```bash
sudo systemctl stop receipts.service
sudo rm /home/receipts/data/receipts.key   # old receipts stay, but their sigs no longer verify
sudo systemctl start receipts.service      # a fresh key is generated at first start
```

To also wipe all receipts: `sudo rm /home/receipts/data/receipts.db` before
restarting. Consider publishing a short notice that receipts issued before
the reset date are no longer verifiable.

## 5. Notes

- Backups: `/home/receipts/data/` is the only state; copy the whole dir
  (db + key) if you want receipt history preserved.
- Logs: the service intentionally logs nothing per-request. `journalctl -u
  receipts.service` shows only start/stop/crash lines.
- Upgrades: replace `receipts.py`, `systemctl restart receipts.service`.
