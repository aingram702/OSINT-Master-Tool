"""
OSINT Master Tool — Flask Backend
Manages tool execution, real-time output streaming via SSE, and built-in utilities.
"""

import base64
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, Response, abort, jsonify, request, send_from_directory
from flask_cors import CORS

from tool_configs import TOOLS, TOOL_CATEGORIES, get_serializable_tools

load_dotenv()

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
MASTER_KEY_FILE = os.path.join(APP_DIR, ".master.key")

# Encryption setup
if not os.path.exists(MASTER_KEY_FILE):
    _key = Fernet.generate_key()
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(_key)
else:
    with open(MASTER_KEY_FILE, "rb") as f:
        _key = f.read()
cipher = Fernet(_key)

# Security Constants & Regex
IP_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
DOMAIN_REGEX = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
URL_REGEX = re.compile(r"^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)$")
CSRF_HEADER = "X-OSINT-CSRF"
CSRF_TOKEN = hashlib.sha256(_key).hexdigest()[:16] # Simple token derived from master key

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")
CORS(app)


def validate_csrf():
    """Verify CSRF token in request headers."""
    token = request.headers.get(CSRF_HEADER)
    if not token or token != CSRF_TOKEN:
        abort(403, description="CSRF token missing or invalid")


def is_safe_path(path):
    """Check if the path is not attempting traversal or accessing system dirs."""
    if not path:
        return True
    path = str(path)
    # Block suspicious patterns
    if ".." in path or path.startswith(("/", "\\")):
        return False
    # On Windows, block drive letters if they look like absolute paths
    if re.match(r"^[a-zA-Z]:", path):
        # Allow absolute paths only if they are within the project Dir (optional, but safer)
        # For now, let's just block absolute paths to be safe, or check them.
        # However, OSINT tools often need paths. Let's at least block system paths.
        low = path.lower()
        if "windows" in low or "system32" in low or "etc/hosts" in low:
            return False
    return True

# ---------------------------------------------------------------------------
# Job Management
# ---------------------------------------------------------------------------
jobs = {}  # job_id -> JobInfo
MAX_OUTPUT_LINES = 5000


class JobInfo:
    def __init__(self, job_id, tool_id, tool_name, command):
        self.job_id = job_id
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.command = command
        self.process = None
        self.output_lines = deque(maxlen=MAX_OUTPUT_LINES)
        self.status = "starting"  # starting | running | completed | failed | stopped
        self.started_at = datetime.now().isoformat()
        self.ended_at = None
        self.return_code = None
        self.listeners = []  # list of threading.Event for SSE

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "command": self.command,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "return_code": self.return_code,
            "output_line_count": len(self.output_lines),
        }


def _read_stream(stream, job, stream_type):
    """Read output from a subprocess stream line by line."""
    try:
        for line in iter(stream.readline, b""):
            try:
                decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
            except Exception:
                decoded = str(line)
            job.output_lines.append({"type": stream_type, "text": decoded, "ts": time.time()})
            # Wake up SSE listeners
            for evt in job.listeners:
                evt.set()
    except Exception:
        pass


def _run_subprocess(job, cmd, cwd, env=None):
    """Execute a subprocess and capture output."""
    try:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        # On Windows use CREATE_NEW_PROCESS_GROUP for reliable termination
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

        job.process = subprocess.Popen(  # nosec B603
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=merged_env,
            creationflags=creation_flags,
        )
        job.status = "running"

        stdout_thread = threading.Thread(target=_read_stream, args=(job.process.stdout, job, "stdout"), daemon=True)
        stderr_thread = threading.Thread(target=_read_stream, args=(job.process.stderr, job, "stderr"), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        job.process.wait()
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        job.return_code = job.process.returncode
        job.status = "completed" if job.return_code == 0 else "failed"
    except Exception as e:
        job.output_lines.append({"type": "stderr", "text": f"Error: {str(e)}", "ts": time.time()})
        job.status = "failed"
    finally:
        job.ended_at = datetime.now().isoformat()
        for evt in job.listeners:
            evt.set()


def build_command(tool_id, params):
    """Build subprocess command from tool config and user params."""
    tool = TOOLS[tool_id]
    cmd = []

    executable = tool.get("executable", "python")
    cmd.append(executable)

    # If script is a module flag
    if tool.get("script") == "-m":
        cmd.append("-m")
        cmd.append(tool.get("module_name", tool_id))
    elif tool.get("script"):
        cmd.append(tool["script"])

    # Collect positional args sorted by position
    positional_args = []
    for arg_def in tool["args"]:
        arg_id = arg_def["id"]
        val = params.get(arg_id)
        if not val and val != 0:
            continue

        if arg_def.get("is_positional"):
            positional_args.append((arg_def.get("position", 99), arg_def, val))
        else:
            flag = arg_def.get("flag")
            if not flag:
                continue

            if arg_def["type"] == "toggle":
                if val and str(val).lower() not in ("false", "0", ""):
                    cmd.append(flag)
            elif arg_def["type"] == "select":
                if val:
                    cmd.append(flag)
                    cmd.append(str(val))
            elif arg_def["type"] == "number":
                cmd.append(flag)
                cmd.append(str(val))
            else:  # text
                if flag == "--site":
                    # Multiple --site flags
                    for site in str(val).split():
                        cmd.append(flag)
                        cmd.append(site)
                elif flag in ("--username", "--email") and " " in str(val):
                    cmd.append(flag)
                    for part in str(val).split():
                        cmd.append(part)
                else:
                    cmd.append(flag)
                    cmd.append(str(val))

    # Add positionals in order
    positional_args.sort(key=lambda x: x[0])
    for _, arg_def, val in positional_args:
        if arg_def["type"] == "text" and " " in str(val) and arg_def.get("id") in ("username",):
            for part in str(val).split():
                cmd.append(part)
        else:
            cmd.append(str(val))

    return cmd


# ---------------------------------------------------------------------------
# Config / Settings (API keys stored with base64 encoding)
# ---------------------------------------------------------------------------
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def encode_key(key_value):
    return cipher.encrypt(key_value.encode("utf-8")).decode("utf-8")


def decode_key(encoded):
    return cipher.decrypt(encoded.encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------------------
# Built-in Tool Implementations
# ---------------------------------------------------------------------------
def _builtin_ip_geolocation(params):
    import urllib.request
    ip = params.get("ip", "").strip()
    if not ip or not IP_REGEX.match(ip):
        return {"error": "A valid IP address is required."}
    try:
        if not url.startswith(("http://", "https://")):
            return {"error": "Only http and https schemes are allowed."}
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Master-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
        if data.get("status") == "fail":
            return {"error": data.get("message", "Lookup failed.")}
        return {"result": data}
    except Exception as e:
        return {"error": str(e)}


def _builtin_whois_lookup(params):
    domain = params.get("domain", "").strip()
    if not domain or not DOMAIN_REGEX.match(domain):
        return {"error": "A valid domain name is required."}
    try:
        import subprocess as sp
        result = sp.run(["nslookup", domain], capture_output=True, text=True, timeout=15, shell=False)  # nosec B603
        lines = []
        lines.append(f"=== WHOIS / DNS Info for {domain} ===\n")

        # Try socket resolution
        try:
            ip = socket.gethostbyname(domain)
            lines.append(f"Resolved IP: {ip}")
        except Exception:
            lines.append("Could not resolve domain.")

        lines.append(f"\n--- nslookup output ---\n{result.stdout}")
        if result.stderr:
            lines.append(f"\n--- errors ---\n{result.stderr}")

        return {"result": "\n".join(lines)}
    except Exception as e:
        return {"error": str(e)}


def _builtin_dns_lookup(params):
    domain = params.get("domain", "").strip()
    record_types_str = params.get("record_types", "A AAAA MX NS TXT CNAME SOA").strip()
    if not domain or not DOMAIN_REGEX.match(domain):
        return {"error": "A valid domain name is required."}

    record_types = record_types_str.split()
    results = {}
    for rtype in record_types:
        try:
            import subprocess as sp
            r = sp.run(["nslookup", f"-type={rtype}", domain], capture_output=True, text=True, timeout=10, shell=False)  # nosec B603
            results[rtype] = r.stdout.strip() if r.stdout.strip() else "No records found."
        except Exception as e:
            results[rtype] = f"Error: {e}"
    return {"result": results}


def _builtin_http_headers(params):
    import urllib.request
    url = params.get("url", "").strip()
    if not url:
        return {"error": "URL is required."}
    if not url.startswith(("http://", "https://")):
        return {"error": "Only http and https schemes are allowed."}
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "OSINT-Master-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            headers = dict(resp.headers)
            security_headers = [
                "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
                "X-Frame-Options", "X-XSS-Protection", "Referrer-Policy",
                "Permissions-Policy", "Cross-Origin-Opener-Policy",
            ]
            analysis = {}
            for sh in security_headers:
                if sh in headers:
                    analysis[sh] = {"status": "present", "value": headers[sh]}
                else:
                    analysis[sh] = {"status": "MISSING", "value": None}
            return {"result": {"headers": headers, "security_analysis": analysis, "status_code": resp.status}}
    except Exception as e:
        return {"error": str(e)}


def _builtin_hash_tool(params):
    mode = params.get("mode", "identify")
    input_text = params.get("input_text", "").strip()
    if not input_text:
        return {"error": "Input is required."}

    if mode == "generate":
        data = input_text.encode("utf-8")
        return {"result": {
            "MD5": hashlib.md5(data).hexdigest(),
            "SHA1": hashlib.sha1(data).hexdigest(),
            "SHA256": hashlib.sha256(data).hexdigest(),
            "SHA512": hashlib.sha512(data).hexdigest(),
        }}
    else:  # identify
        h = input_text.strip()
        patterns = [
            (r"^[a-fA-F0-9]{32}$", "MD5"),
            (r"^[a-fA-F0-9]{40}$", "SHA1"),
            (r"^[a-fA-F0-9]{64}$", "SHA256"),
            (r"^[a-fA-F0-9]{128}$", "SHA512"),
            (r"^\$2[ayb]\$.{56}$", "bcrypt"),
            (r"^\$6\$", "SHA-512 crypt"),
            (r"^\$5\$", "SHA-256 crypt"),
            (r"^\$1\$", "MD5 crypt"),
            (r"^[a-fA-F0-9]{16}$", "MySQL (old) / Half MD5"),
            (r"^[a-fA-F0-9]{56}$", "SHA224"),
            (r"^[a-fA-F0-9]{96}$", "SHA384"),
        ]
        identified = []
        for pattern, name in patterns:
            if re.match(pattern, h):
                identified.append(name)
        if not identified:
            identified = ["Unknown hash type"]
        return {"result": {"input": h, "possible_types": identified, "length": len(h)}}


def _builtin_subdomain_finder(params):
    import urllib.request
    domain = params.get("domain", "").strip()
    if not domain or not DOMAIN_REGEX.match(domain):
        return {"error": "A valid domain name is required."}
    try:
        if not url.startswith(("http://", "https://")):
            return {"error": "Only http and https schemes are allowed."}
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Master-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and "*" not in sub:
                    subdomains.add(sub)
        sorted_subs = sorted(subdomains)
        return {"result": {"domain": domain, "count": len(sorted_subs), "subdomains": sorted_subs}}
    except Exception as e:
        return {"error": str(e)}


def _builtin_url_unshortener(params):
    import urllib.request
    url = params.get("url", "").strip()
    if not url:
        return {"error": "URL is required."}
    if not url.startswith(("http://", "https://")):
        return {"error": "Only http and https schemes are allowed."}
    try:
        chain = [url]
        current = url
        for _ in range(15):  # max 15 redirects
            if not current.startswith(("http://", "https://")):
                break
            req = urllib.request.Request(current, method="HEAD", headers={"User-Agent": "OSINT-Master-Tool/1.0"})
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
            try:
                resp = opener.open(req, timeout=10) # nosec B310
                final = resp.url
                if final == current:
                    break
                chain.append(final)
                current = final
            except urllib.request.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get("Location", "")
                    if loc:
                        chain.append(loc)
                        current = loc
                    else:
                        break
                else:
                    break
            except Exception:
                break
        return {"result": {"original": url, "final": chain[-1], "redirect_chain": chain, "hops": len(chain) - 1}}
    except Exception as e:
        return {"error": str(e)}


def _builtin_tech_detector(params):
    import urllib.request
    url = params.get("url", "").strip()
    if not url:
        return {"error": "URL is required."}
    if not url.startswith(("http://", "https://")):
        return {"error": "Only http and https schemes are allowed."}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Master-Tool/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            headers = dict(resp.headers)
            body = resp.read(50000).decode("utf-8", errors="replace")

        detected = []
        # Server header
        if "Server" in headers:
            detected.append({"tech": "Server", "detail": headers["Server"]})
        if "X-Powered-By" in headers:
            detected.append({"tech": "Powered By", "detail": headers["X-Powered-By"]})

        # Framework detection from body
        tech_signatures = [
            ("React", [r"react", r"__NEXT_DATA__", r"_next/", r"reactroot"]),
            ("Next.js", [r"__NEXT_DATA__", r"_next/static"]),
            ("Vue.js", [r"vue\.js", r"__vue__", r"vue-router"]),
            ("Angular", [r"ng-version", r"angular\.js", r"ng-app"]),
            ("jQuery", [r"jquery", r"jQuery"]),
            ("Bootstrap", [r"bootstrap\.min\.(css|js)", r"bootstrap\."]),
            ("WordPress", [r"wp-content", r"wp-includes", r"wordpress"]),
            ("Drupal", [r"drupal\.js", r"Drupal\.settings"]),
            ("Joomla", [r"joomla", r"/media/system/js/"]),
            ("Shopify", [r"shopify", r"cdn\.shopify\.com"]),
            ("Django", [r"csrfmiddlewaretoken", r"__admin_media_prefix__"]),
            ("Flask", [r"werkzeug", r"flask"]),
            ("Laravel", [r"laravel", r"csrf-token"]),
            ("Ruby on Rails", [r"rails", r"csrf-token.*authenticity"]),
            ("ASP.NET", [r"__VIEWSTATE", r"aspnet", r"asp\.net"]),
            ("Cloudflare", [r"cloudflare", r"cf-ray"]),
            ("Google Analytics", [r"google-analytics\.com", r"gtag", r"UA-\d+"]),
            ("Google Tag Manager", [r"googletagmanager\.com"]),
            ("Nginx", [r"nginx"]),
            ("Apache", [r"apache"]),
        ]
        for tech_name, patterns in tech_signatures:
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, str(headers), re.IGNORECASE):
                    if not any(d["tech"] == tech_name for d in detected):
                        detected.append({"tech": tech_name, "detail": "Detected in response"})
                    break

        return {"result": {"url": url, "technologies": detected, "count": len(detected)}}
    except Exception as e:
        return {"error": str(e)}


BUILTIN_HANDLERS = {
    "ip_geolocation": _builtin_ip_geolocation,
    "whois_lookup": _builtin_whois_lookup,
    "dns_lookup": _builtin_dns_lookup,
    "http_headers": _builtin_http_headers,
    "hash_tool": _builtin_hash_tool,
    "subdomain_finder": _builtin_subdomain_finder,
    "url_unshortener": _builtin_url_unshortener,
    "tech_detector": _builtin_tech_detector,
}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/tools")
def api_tools():
    """Return all tool configurations for the frontend."""
    data = get_serializable_tools()
    data["csrf_token"] = CSRF_TOKEN
    return jsonify(data)


@app.route("/api/run", methods=["POST"])
def api_run():
    """Start a tool execution and return a job ID."""
    validate_csrf()
    data = request.json
    tool_id = data.get("tool_id")
    params = data.get("params", {})

    if tool_id not in TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 400

    tool = TOOLS[tool_id]

    # Path safety check for all param values
    for k, v in params.items():
        if not is_safe_path(v):
            return jsonify({"error": f"Invalid path detected in parameter '{k}'"}), 400

    # Create job
    job_id = str(uuid.uuid4())[:8]
    job = JobInfo(job_id, tool_id, tool["name"], "Pending...")
    jobs[job_id] = job

    # Built-in tools
    if tool.get("builtin"):
        handler = BUILTIN_HANDLERS.get(tool_id)
        if not handler:
            return jsonify({"error": f"No handler for built-in tool: {tool_id}"}), 500

        def run_builtin():
            try:
                job.status = "running"
                job.output_lines.append({"type": "stdout", "text": f"Starting built-in tool: {tool['name']}...", "ts": time.time()})
                result = handler(params)
                if "error" in result:
                    job.output_lines.append({"type": "stderr", "text": result["error"], "ts": time.time()})
                    job.status = "failed"
                else:
                    job.output_lines.append({"type": "stdout", "text": "Execution completed successfully.", "ts": time.time()})
                    job.output_lines.append({"type": "stdout", "text": f"DATA_RESULT:{json.dumps(result)}", "ts": time.time()})
                    job.status = "completed"
            except Exception as e:
                job.output_lines.append({"type": "stderr", "text": f"Error: {e}", "ts": time.time()})
                job.status = "failed"
            finally:
                job.ended_at = datetime.now().isoformat()
                for evt in job.listeners:
                    evt.set()

        threading.Thread(target=run_builtin, daemon=True).start()
        return jsonify({"job_id": job_id, "status": "starting", "builtin": True})

    # Build command for external tools
    try:
        cmd = build_command(tool_id, params)
        job.command = " ".join(cmd)
    except Exception as e:
        return jsonify({"error": f"Failed to build command: {e}"}), 400

    # Inject API keys from config if needed
    env = {}
    if tool.get("requires_api_key"):
        cfg = load_config()
        key_name = tool["requires_api_key"]
        encoded = cfg.get("api_keys", {}).get(key_name)
        if encoded:
            try:
                env[key_name.upper()] = decode_key(encoded)
            except Exception:
                return jsonify({"error": "Failed to decrypt API key. Please re-save it in Settings."}), 500

    cwd = tool.get("cwd", APP_DIR)
    threading.Thread(target=_run_subprocess, args=(job, cmd, cwd, env if env else None), daemon=True).start()

    return jsonify({"job_id": job_id, "command": job.command, "status": "starting"})


@app.route("/api/stream/<job_id>")
def api_stream(job_id):
    """SSE endpoint for streaming job output."""
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404

    job = jobs[job_id]

    def generate():
        last_idx = 0
        evt = threading.Event()
        job.listeners.append(evt)

        try:
            while True:
                # Send any new output lines
                current_lines = list(job.output_lines)
                if last_idx < len(current_lines):
                    for line_info in current_lines[last_idx:]:
                        payload = json.dumps(line_info)
                        yield f"data: {payload}\n\n"
                    last_idx = len(current_lines)

                # Send status update
                yield f"event: status\ndata: {json.dumps({'status': job.status, 'return_code': job.return_code})}\n\n"

                if job.status in ("completed", "failed", "stopped"):
                    yield f"event: done\ndata: {json.dumps(job.to_dict())}\n\n"
                    break

                # Wait for new data (max 2 seconds to keep connection alive)
                evt.wait(timeout=2)
                evt.clear()
        finally:
            if evt in job.listeners:
                job.listeners.remove(evt)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/stop/<job_id>", methods=["POST"])
def api_stop(job_id):
    """Stop a running job."""
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404

    job = jobs[job_id]
    if job.process and job.process.poll() is None:
        try:
            if sys.platform == "win32":
                job.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                job.process.terminate()
            job.process.wait(timeout=5)
        except Exception:
            job.process.kill()
        job.status = "stopped"
        job.ended_at = datetime.now().isoformat()
        for evt in job.listeners:
            evt.set()
        return jsonify({"status": "stopped"})
    return jsonify({"status": job.status})


@app.route("/api/jobs")
def api_jobs():
    """List all jobs."""
    return jsonify([j.to_dict() for j in reversed(list(jobs.values()))])


@app.route("/api/job/<job_id>/output")
def api_job_output(job_id):
    """Get full output for a job."""
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404
    job = jobs[job_id]
    return jsonify({"output": list(job.output_lines), "status": job.status})


@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    cfg = load_config()
    # Mask API keys for display
    safe = dict(cfg)
    if "api_keys" in safe:
        safe["api_keys"] = {k: "••••••••" for k in safe["api_keys"]}
    return jsonify(safe)


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    validate_csrf()
    data = request.json
    cfg = load_config()

    if "api_keys" in data:
        if "api_keys" not in cfg:
            cfg["api_keys"] = {}
        for key_name, key_value in data["api_keys"].items():
            if key_value and key_value != "••••••••":
                try:
                    cfg["api_keys"][key_name] = encode_key(key_value)
                except Exception as e:
                    return jsonify({"error": f"Encryption failed for {key_name}: {e}"}), 500

    if "theme" in data:
        cfg["theme"] = data["theme"]

    save_config(cfg)
    return jsonify({"status": "saved"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(r"""
   ____  _____ _____ _   _ _____   __  __           _
  / __ \/ ____|_   _| \ | |_   _| |  \/  |         | |
 | |  | | (___  | | |  \| | | |   | \  / | __ _ ___| |_ ___ _ __
 | |  | |\___ \ | | | . ` | | |   | |\/| |/ _` / __| __/ _ \ '__|
 | |__| |____) || |_| |\  | | |   | |  | | (_| \__ \ ||  __/ |
  \____/|_____/_____|_| \_| |_|   |_|  |_|\__,_|___/\__\___|_|
                                                    Tool v1.0
    """)
    print(f"  Starting OSINT Master Tool on http://127.0.0.1:5000")
    print(f"  Static files: {STATIC_DIR}")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
