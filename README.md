# VulnScan Console

A web-based orchestration layer for network vulnerability assessment. It drives
existing pentesting tools (nmap, nuclei, nikto, …) as pluggable add-ons,
streams their output to the browser in real time, aggregates findings, and
produces CVE-oriented reports.

This is **step 1: the framework and interface.** The scan engine, plugin
system, realtime console, findings feed and history are working end to end. A
built-in *Demo Scanner* lets you exercise everything before installing any real
tools.

## Authorised use only

This tool executes active scans against hosts. **Only assess systems you own or
have explicit written authorisation to test.** As a guard rail, scans are
restricted to internal/private IP ranges by default. Set `ALLOW_EXTERNAL=true`
only when you have authorisation for external targets and understand the legal
implications. Unauthorised scanning may be illegal in your jurisdiction.

## Run it (local)

```bash
cp .env.example .env      # adjust if needed
./run.sh
# → http://127.0.0.1:8000
```

Pick **Demo Scanner**, enter a target like `192.168.1.10`, and launch. You'll
see the streaming console fill and findings appear live.

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Bind address |
| `DATA_DIR` | `./data` | SQLite location |
| `ALLOW_EXTERNAL` | `false` | Permit non-private targets |
| `EXTRA_SCOPE_CIDRS` | – | Extra authorised ranges, comma separated |
| `MAX_CONCURRENT_SCANS` | `4` | Concurrency cap |

## Install real tools

Plugins activate automatically once their binary is on `$PATH`:

```bash
sudo apt install nmap nikto
# nuclei: https://github.com/projectdiscovery/nuclei
```

## Deploy on Ubuntu (systemd + nginx)

Runs the app as a service on `127.0.0.1:8000` behind nginx, which adds a login
and (optionally) TLS. Native install is recommended for a scanner because it
gets direct access to your network.

```bash
# 1. System dependencies
sudo apt update
sudo apt install -y python3-venv nginx apache2-utils nmap nikto

# 2. Put the code in place
sudo git clone https://github.com/YOURUSER/vulnscan.git /opt/vulnscan
sudo useradd --system --home /opt/vulnscan --shell /usr/sbin/nologin vulnscan

# 3. Virtualenv + dependencies
sudo python3 -m venv /opt/vulnscan/backend/.venv
sudo /opt/vulnscan/backend/.venv/bin/pip install -r /opt/vulnscan/backend/requirements.txt

# 4. Configuration
sudo cp /opt/vulnscan/.env.example /opt/vulnscan/.env
sudo sed -i 's/^HOST=.*/HOST=127.0.0.1/' /opt/vulnscan/.env
sudo chown -R vulnscan:vulnscan /opt/vulnscan

# 5. Service
sudo cp /opt/vulnscan/deploy/vulnscan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnscan
systemctl status vulnscan --no-pager

# 6. Reverse proxy + login
sudo htpasswd -c /etc/nginx/.vulnscan.htpasswd youruser
sudo cp /opt/vulnscan/deploy/nginx.conf /etc/nginx/sites-available/vulnscan
# edit server_name in that file, then:
sudo ln -s /etc/nginx/sites-available/vulnscan /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 7. (optional) TLS
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d vulnscan.example.com
```

Update later with:

```bash
cd /opt/vulnscan && sudo git pull
sudo /opt/vulnscan/backend/.venv/bin/pip install -r backend/requirements.txt
sudo systemctl restart vulnscan
```

Logs: `journalctl -u vulnscan -f`

## Deploy with Docker

```bash
cp .env.example .env
docker compose up -d --build
# → http://localhost:8000
```

The image bundles nmap and nikto. For full LAN host discovery from inside the
container, switch to host networking in `docker-compose.yml` (commented there).

## Architecture

```
backend/
  app.py            FastAPI: REST + WebSocket + static serving
  scanner.py        Orchestration: spawn tools, stream, persist, cancel
  ws.py             WebSocket event fan-out
  models.py         Schemas + SQLite store (scans, findings)
  config.py         Scope guard rail, limits
  plugins/
    base.py         BasePlugin contract (the add-on interface)
    __init__.py     Auto-discovery registry
    demo.py         Simulated reference plugin
    nmap.py nuclei.py nikto.py
frontend/           Vanilla JS console (no build step)
```

Events flow: **tool stdout → scanner → EventHub → WebSocket → console/findings.**

## Add a tool (the add-on model)

Create `backend/plugins/yourtool.py`:

```python
from .base import BasePlugin

class YourToolPlugin(BasePlugin):
    slug = "yourtool"
    name = "Your Tool"
    description = "What it does."
    category = "Web"
    binary = "yourtool"           # checked on $PATH
    options_schema = [
        {"key": "aggressive", "label": "Aggressive", "type": "checkbox", "default": False},
    ]

    def build_command(self, target, options):
        cmd = ["yourtool", target]
        if options.get("aggressive"):
            cmd.append("--aggressive")
        return cmd

    def parse_line(self, line):          # incremental findings
        return []

    def finalize(self, lines, target):   # whole-output findings
        return []
```

Drop the file in and restart — it self-registers and appears in the tool
dropdown. Findings you return (`name`, `severity`, `cve`, `port`,
`description`, `evidence`) are persisted and rendered live.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/plugins`            | Available tools + option schemas |
| POST | `/api/scans`              | Start a scan |
| GET  | `/api/scans`              | Scan history |
| GET  | `/api/scans/{id}`         | Scan detail + findings |
| POST | `/api/scans/{id}/cancel`  | Stop a running scan |
| GET  | `/api/report?scan_id=`    | CVE report payload (JSON) |
| WS   | `/ws`                     | Realtime event stream |

## Not done yet (next steps)

- Rendered HTML/PDF reports (currently JSON export)
- Authentication / multi-user
- Scan scheduling and asset inventory
- Result de-duplication across tools
