# Careful merged file

import json
import os
import shutil
import tempfile
import time
import random
import itertools
import string
import logging
import subprocess
import copy
import warnings
import threading
from collections import Counter
from datetime import datetime
from typing import Dict, Any

# deployer module
try:
    from modules import deployer as deployer_mod
except Exception:
    deployer_mod = None

# Suppress DeprecationWarning from datetime.utcnow usage in this script
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Module logger
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Centralized runtime live-action gate (default enabled for autonomous mode). Set via set_live_allowed(bool) or Queen will set it on init.
LIVE_ALLOWED = True

def set_live_allowed(val: bool):
    global LIVE_ALLOWED
    LIVE_ALLOWED = bool(val)

def live_allowed():
    return bool(LIVE_ALLOWED)

# Default max workers for thread pools (safe, configurable)
DEFAULT_MAX_WORKERS = min(32, (os.cpu_count() or 1) * 4)

# Default scan tuning parameters
DEFAULT_SCAN_PORTS = [80, 443, 53, 22]
DEFAULT_SCAN_TIMEOUT = 0.5  # seconds per connection
DEFAULT_SCHEDULE_INTERVAL = 600  # seconds
DEFAULT_SCHEDULE_ROUNDS = 3
DEFAULT_SCHEDULE_CONCURRENCY = 12

# Scoring defaults
DEFAULT_SCORING_WEIGHTS = {
    'per_port': 2,
    'found_in_last': 3,
    'service_banner': 4,
    'http_headers_present': 5,
    'server_known': 3,
    'www_auth': 5,
    'security_headers': 1,
    'tls_present': 6,
    'tls_san': 3,
    'tls_valid': 2,
}

# Logs dir for scheduled scans
SCHEDULE_LOG_DIR = os.path.join('.', 'logs')
SCHEDULE_LOG_FILE = os.path.join(SCHEDULE_LOG_DIR, 'scheduled_scans.jsonl')

# Simple symmetric XOR encrypt/decrypt for storing credentials with passphrase-derived key
import base64, hashlib

def _derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode('utf-8')).digest()

def encrypt_blob(data: str, passphrase: str) -> str:
    key = _derive_key(passphrase)
    b = data.encode('utf-8')
    out = bytearray()
    for i, byte in enumerate(b):
        out.append(byte ^ key[i % len(key)])
    return base64.b64encode(bytes(out)).decode('utf-8')

def decrypt_blob(blob_b64: str, passphrase: str) -> str:
    try:
        key = _derive_key(passphrase)
        raw = base64.b64decode(blob_b64)
        out = bytearray()
        for i, byte in enumerate(raw):
            out.append(byte ^ key[i % len(key)])
        return bytes(out).decode('utf-8')
    except Exception:
        raise


# Telemetry shim
class Telemetry:
    def snapshot(self):
        return {"cpu_pct":0, "mem_mb":0, "traits": []}
    def environment(self):
        return {"avg_cpu_pct":0.0, "avg_mem_mb":0.0}

# Filesystem knowledge base (high-level mapping, used for safe recommendations)
FILESYSTEM_KNOWLEDGE = {
    "linux": {
        "bin": "/bin, /usr/bin - executable binaries",
        "etc": "/etc - configuration files",
        "var": "/var - variable data (logs, spools)",
        "home": "/home - user data",
        "lib": "/lib - shared libraries",
    },
    "windows": {
        "system32": "C:\\Windows\\System32 - core OS binaries",
        "program_files": "C:\\Program Files - installed programs",
        "users": "C:\\Users - user profiles and data",
        "appdata": "%APPDATA% - per-user application data",
    },
    "android": {
        "system": "/system - read-only system image",
        "data": "/data - app data and user data",
        "sdcard": "/sdcard - external storage",
    },
    "macos": {
        "system": "/System - OS components",
        "library": "/Library - system-wide libraries and settings",
        "users": "/Users - user directories",
        "applications": "/Applications - installed apps",
    }
}

# Safe connector stubs. Live actions disabled by default; require queen.allow_live True and credentials.
class TransportBase:
    """Unified transport interface. Connectors should expose a consistent shape: 
    - name: short name
    - connect(timeout)
    - close()
    - run_cmd(cmd)
    - put(local, remote) (optional)
    - health() -> dict(status: 'ok'|'disabled'|'not_configured'|'error', detail:str)

    Provides a simple cached health() wrapper via health_cached to avoid repeated blocking probes.
    """
    name = 'base'

    def __init__(self):
        self.last_error = None
        self._health_cache = None  # {ts: float, val: dict}

    def connect(self, timeout=5):
        raise NotImplementedError

    def close(self):
        pass

    def run_cmd(self, *args, **kwargs):
        raise NotImplementedError

    def put(self, *args, **kwargs):
        raise NotImplementedError

    def health(self, timeout=1.0):
        return {"name": self.name, "status": "not_implemented", "detail": None}

    def health_cached(self, timeout=1.0, ttl=2.0):
        import time
        now = time.time()
        if self._health_cache and (now - self._health_cache.get('ts', 0) < ttl):
            return self._health_cache.get('val')
        try:
            val = self.health(timeout=timeout)
        except Exception as e:
            val = {"name": self.name, "status": "error", "detail": str(e)}
        self._health_cache = {'ts': now, 'val': val}
        return val


class SSHConnector(TransportBase):
    name = 'ssh'

    def __init__(self, host=None, port=22, user=None, key=None, password=None, allow_live=False):
        super().__init__()
        self.host = host
        self.port = int(port) if port is not None else None
        self.user = user
        self.key = key
        self.password = password
        self.allow_live = allow_live
        self._client = None

    def connect(self, timeout=5):
        if not (self.allow_live and LIVE_ALLOWED):
            self.last_error = 'live disabled'
            return False, "live disabled"
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.key:
                client.connect(self.host, port=self.port, username=self.user, key_filename=self.key, timeout=timeout)
            else:
                client.connect(self.host, port=self.port, username=self.user, password=self.password, timeout=timeout)
            self._client = client
            return True, "connected"
        except Exception as e:
            self.last_error = str(e)
            return False, str(e)

    def run_cmd(self, cmd, timeout=10):
        if not self._client:
            ok, msg = self.connect()
            if not ok:
                return False, msg
        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            return True, stdout.read().decode(errors='ignore')
        except Exception as e:
            self.last_error = str(e)
            return False, str(e)

    def close(self):
        if self._client:
            try:
                self._client.close()
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass

    def health(self, timeout=1.0):
        # lightweight TCP check for reachability
        if not self.host:
            return {"name": self.name, "status": "not_configured", "detail": "no host"}
        if not (self.allow_live and LIVE_ALLOWED):
            return {"name": self.name, "status": "disabled", "detail": "live disabled"}
        try:
            import socket, time as _time
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            start = _time.time()
            res = s.connect_ex((self.host, int(self.port)))
            elapsed = (_time.time() - start) * 1000.0
            s.close()
            if res == 0:
                return {"name": self.name, "status": "ok", "detail": f"tcp_ok {elapsed:.1f}ms"}
            else:
                return {"name": self.name, "status": "error", "detail": f"tcp_failed code={res}"}
        except Exception as e:
            return {"name": self.name, "status": "error", "detail": str(e)}

class ADBConnector(TransportBase):
    """Minimal ADB wrapper that uses adb executable if allowed. Disabled unless allow_live True and ADB in PATH."""
    name = 'adb'

    def __init__(self, device=None, allow_live=False):
        super().__init__()
        self.device = device
        self.allow_live = allow_live

    def shell(self, cmd, timeout=10):
        if not (self.allow_live and LIVE_ALLOWED):
            self.last_error = 'live disabled'
            return False, "live disabled"
        try:
            args = ["adb"]
            if self.device:
                args += ["-s", self.device]
            args += ["shell", cmd]
            out = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout)
            return True, out.decode(errors='ignore')
        except Exception as e:
            self.last_error = str(e)
            return False, str(e)

    def health(self, timeout=1.0):
        import shutil
        if not self.device:
            return {"name": self.name, "status": "not_configured", "detail": "no device"}
        if not shutil.which('adb'):
            return {"name": self.name, "status": "error", "detail": "adb missing"}
        if not (self.allow_live and LIVE_ALLOWED):
            return {"name": self.name, "status": "disabled", "detail": "live disabled"}
        # best-effort probe: list devices
        try:
            out = subprocess.check_output(['adb', 'devices'], stderr=subprocess.DEVNULL, timeout=timeout)
            txt = out.decode(errors='ignore')
            if self.device in txt:
                return {"name": self.name, "status": "ok", "detail": "device_present"}
            return {"name": self.name, "status": "error", "detail": "device_not_listed"}
        except Exception as e:
            return {"name": self.name, "status": "error", "detail": str(e)}

class SCPConnector(TransportBase):
    name = 'scp'

    def __init__(self, host=None, port=22, user=None, key=None, password=None, allow_live=False):
        super().__init__()
        self.ssh = SSHConnector(host, port, user, key, password, allow_live)

    def put(self, local, remote):
        if not (self.ssh.allow_live and LIVE_ALLOWED):
            self.last_error = 'live disabled'
            return False, 'live disabled'
        try:
            import paramiko
            transport = paramiko.Transport((self.ssh.host, self.ssh.port))
            if self.ssh.key:
                pkey = paramiko.RSAKey.from_private_key_file(self.ssh.key)
                transport.connect(username=self.ssh.user, pkey=pkey)
            else:
                transport.connect(username=self.ssh.user, password=self.ssh.password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.put(local, remote)
            sftp.close()
            transport.close()
            return True, 'ok'
        except Exception as e:
            self.last_error = str(e)
            return False, str(e)

    def health(self, timeout=1.0):
        return self.ssh.health(timeout=timeout)

class TCPConnector(TransportBase):
    name = 'tcp'

    def __init__(self, host=None, port=None, allow_live=False):
        super().__init__()
        self.host = host
        self.port = int(port) if port is not None else None
        self.allow_live = allow_live

    def connect(self, timeout=1.0):
        if not (self.allow_live and LIVE_ALLOWED):
            self.last_error = 'live disabled'
            return False, 'live disabled'
        if not self.host or self.port is None:
            self.last_error = 'not configured'
            return False, 'not configured'
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((self.host, int(self.port)))
            s.close()
            ok = (res == 0)
            if not ok:
                self.last_error = f'connect_ex={res}'
            return ok, res
        except Exception as e:
            self.last_error = str(e)
            return False, str(e)

    def health(self, timeout=1.0):
        if not self.host or self.port is None:
            return {"name": self.name, "status": "not_configured", "detail": "no host/port"}
        try:
            import socket, time as _time
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            start = _time.time()
            res = s.connect_ex((self.host, int(self.port)))
            elapsed = (_time.time() - start) * 1000.0
            s.close()
            if res == 0:
                return {"name": self.name, "status": "ok", "detail": f"tcp_ok {elapsed:.1f}ms"}
            else:
                return {"name": self.name, "status": "error", "detail": f"tcp_failed code={res}"}
        except Exception as e:
            return {"name": self.name, "status": "error", "detail": str(e)}

# Helper to safely merge genetic memory between queens
def merge_genetic_memory(dest_list, src_list):
    for item in src_list:
        if item not in dest_list:
            dest_list.append(item)
    return dest_list


# --- Scanner backends and layered discovery helpers ---
class BaseScanner:
    """Abstract scanner backend."""
    def __init__(self, timeout=0.5, ports=None):
        self.timeout = float(timeout)
        self.ports = ports or []

    def arp_scan(self, cidr):
        return []

    def icmp_ping(self, ip):
        return False

    def tcp_scan(self, ip, ports):
        return []

    def udp_probe(self, ip, ports):
        return []

    def masscan(self, cidr, ports):
        return []

    def nmap(self, ip, ports):
        return {}


class ScanResult:
    """Unified scan result schema used by scanners and downstream consumers.
    Fields:
      - ip (str)
      - open_ports (list[int])
      - protocols (list[str])
      - banners (dict)  # e.g. {port: banner_text}
      - source (str)    # scanner name
      - confidence (float) # 0.0-1.0
    """
    def __init__(self, ip, open_ports=None, protocols=None, banners=None, source=None, confidence=0.0):
        self.ip = ip
        self.open_ports = list(open_ports or [])
        self.protocols = list(protocols or [])
        self.banners = dict(banners or {})
        self.source = source or 'unknown'
        self.confidence = float(confidence)

    def to_dict(self):
        return {
            'ip': self.ip,
            'open_ports': self.open_ports,
            'protocols': self.protocols,
            'banners': self.banners,
            'source': self.source,
            'confidence': self.confidence,
        }

    def __repr__(self):
        return f"ScanResult(ip={self.ip}, open_ports={self.open_ports}, source={self.source}, conf={self.confidence})"


class ScanFusion:
    """Simple fusion utilities for ScanResult lists."""
    @staticmethod
    def fuse(results):
        """Fuse multiple ScanResult objects into a dict ip->ScanResult combining ports and averaging confidence."""
        merged = {}
        for r in (results or []):
            if not r or not getattr(r, 'ip', None):
                continue
            ip = r.ip
            ei = merged.get(ip)
            if not ei:
                merged[ip] = ScanResult(ip=ip, open_ports=list(r.open_ports), protocols=list(r.protocols), banners=dict(r.banners), source='fused', confidence=r.confidence)
            else:
                # combine ports
                existing_ports = set(ei.open_ports)
                existing_ports.update(r.open_ports)
                ei.open_ports = sorted(list(existing_ports))
                # merge protocols
                existing_protos = set(ei.protocols)
                existing_protos.update(r.protocols)
                ei.protocols = sorted(list(existing_protos))
                # merge banners
                ei.banners.update(r.banners or {})
                # average confidence
                ei.confidence = min(1.0, (ei.confidence + r.confidence) / 2.0)
        return list(merged.values())

    @staticmethod
    def to_summary(results):
        """Return a compact summary list of dicts for display/logging."""
        return [r.to_dict() for r in (results or [])]


class TCPConnectScanner(BaseScanner):
    def tcp_scan(self, ip, ports):
        import socket
        found = []
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                res = s.connect_ex((ip, int(p)))
                s.close()
                if res == 0:
                    found.append(int(p))
            except Exception:
                continue
        return found

    def scan_ip(self, ip, ports=None):
        """Return a ScanResult for a single IP using TCP connect probes."""
        ports = ports or self.ports or [22, 80, 443]
        open_ports = self.tcp_scan(ip, ports)
        conf = min(1.0, 0.1 + 0.2 * len(open_ports))
        sr = ScanResult(ip=ip, open_ports=open_ports, protocols=['tcp'] if open_ports else [], banners={}, source='tcp_connect', confidence=conf)
        return sr

    def icmp_ping(self, ip):
        # Best-effort: try TCP connect to common ports as proxy for reachability
        for p in (80, 443, 22):
            try:
                s = __import__('socket').socket(__import__('socket').AF_INET, __import__('socket').SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip, p)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False


class MasscanScanner(BaseScanner):
    def masscan(self, cidr, ports):
        # masscan usage: masscan -p80,443 --open --rate 1000 10.0.0.0/24 -oJ -
        try:
            import shutil, subprocess, json
            if not shutil.which('masscan'):
                return []
            port_str = ','.join(str(p) for p in (ports or self.ports))
            cmd = ['masscan', '-p', port_str, '--open', '--rate', '1000', cidr, '-oJ', '-']
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=max(10, int(self.timeout*10)))
            data = json.loads(out.decode('utf-8', errors='ignore'))
            ips = {}
            for entry in data:
                if entry.get('ip'):
                    ip = entry['ip']
                    ports = ips.setdefault(ip, [])
                    if 'ports' in entry:
                        for p in entry['ports']:
                            ports.append(int(p.get('port')))
            return ips
        except Exception:
            return {}

    def scan_cidr(self, cidr, ports=None):
        """Return a list of ScanResult entries from a masscan run (best-effort)."""
        res = []
        try:
            findings = self.masscan(cidr, ports or self.ports)
            for ip, ports in (findings or {}).items():
                conf = min(1.0, 0.2 + 0.1 * len(ports))
                sr = ScanResult(ip=ip, open_ports=ports, protocols=['tcp'], banners={}, source='masscan', confidence=conf)
                res.append(sr)
        except Exception:
            pass
        return res


class NmapScanner(BaseScanner):
    def nmap(self, ip, ports):
        try:
            import shutil, subprocess
            if not shutil.which('nmap'):
                return {}
            port_str = ','.join(str(p) for p in ports)
            cmd = ['nmap', '-Pn', '-p', port_str, ip, '--open', '-oG', '-']
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=max(5, int(self.timeout*10)))
            text = out.decode('utf-8', errors='ignore')
            res_ports = {}
            for line in text.splitlines():
                if line.startswith('#'):
                    continue
                if 'Ports:' in line:
                    # parse e.g. Ports: 22/open/tcp//ssh///
                    parts = line.split('Ports:')[-1].strip()
                    for seg in parts.split(','):
                        seg = seg.strip()
                        if '/' in seg:
                            p = seg.split('/')[0]
                            try:
                                res_ports[int(p)] = True
                            except Exception:
                                pass
            return {'open_ports': list(res_ports.keys())}
        except Exception:
            return {}

    def scan_ip(self, ip, ports=None):
        """Return a ScanResult produced from nmap for a single IP."""
        try:
            nres = self.nmap(ip, ports or self.ports)
            open_ports = nres.get('open_ports') if isinstance(nres, dict) else []
            conf = min(1.0, 0.3 + 0.15 * len(open_ports))
            return ScanResult(ip=ip, open_ports=open_ports, protocols=['tcp'], banners={}, source='nmap', confidence=conf)
        except Exception:
            return ScanResult(ip=ip, open_ports=[], source='nmap', confidence=0.0)


# Lightweight SSDP and mDNS probes
def ssdp_probe(timeout=1.0):
    results = []
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        msg = '\r\n'.join([
            'M-SEARCH * HTTP/1.1',
            'HOST: 239.255.255.250:1900',
            'MAN: "ssdp:discover"',
            'MX: 2',
            'ST: ssdp:all',
            '',
            ''
        ]).encode('utf-8')
        s.sendto(msg, ('239.255.255.250', 1900))
        try:
            while True:
                data, addr = s.recvfrom(2048)
                results.append((addr[0], data.decode('utf-8', errors='ignore')))
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return results


def mdns_probe(timeout=1.0):
    results = []
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'\x00', ('224.0.0.251', 5353))
        try:
            while True:
                data, addr = s.recvfrom(4096)
                results.append((addr[0], data))
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return results


def grab_http_banner(ip, port=80, timeout=1.0):
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        req = b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % ip.encode('utf-8')
        s.send(req)
        data = s.recv(1024)
        s.close()
        return data.decode('utf-8', errors='ignore')
    except Exception:
        return ''


def grab_http_headers(ip, port=80, timeout=1.0, use_ssl=False):
    """Perform a HEAD request and return headers dict (best-effort)."""
    try:
        import socket, ssl
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.connect((ip, port))
        req = f'HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n'.encode('utf-8')
        s.send(req)
        data = b''
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            except Exception:
                break
        s.close()
        text = data.decode('utf-8', errors='ignore')
        parts = text.split('\r\n\r\n', 1)
        hdr_text = parts[0] if parts else text
        lines = hdr_text.splitlines()
        headers = {}
        for ln in lines[1:]:
            if ':' in ln:
                k, v = ln.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        return headers
    except Exception:
        return {}


def grab_tls_cert(ip, port=443, timeout=2.0):
    try:
        import socket, ssl
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        context = ssl.create_default_context()
        ss = context.wrap_socket(s, server_hostname=ip)
        ss.connect((ip, port))
        cert = ss.getpeercert()
        ss.close()
        return cert
    except Exception:
        return None


# --- Begin: Modules/Trait_defs.py ---

# Modules/Trait_defs.py

"""
Trait definitions for telemetry scoring.
Each trait_def specifies how score_trait should evaluate the brood's fitness report.
"""

# Boolean evaluators
def eval_open_ports(brood, target):
    return 2 if brood.fitness_report().get("open_ports", 0) >= target else 0

def eval_blocked_ports(brood, target):
    return 2 if brood.fitness_report().get("blocked_ports", 0) <= target else 0

def eval_ips_discovered(brood, target):
    return 2 if brood.fitness_report().get("ips_discovered", 0) >= target else 0


TRAIT_DEFS = {
    # --- Numeric traits ---
    "latency": {
        "target_type": "number",
        "direction": "min",
        "tolerance": 0.2
    },
    "packet_loss": {
        "target_type": "number",
        "direction": "min",
        "tolerance": 0.1
    },
    "bandwidth_efficiency": {
        "target_type": "number",
        "direction": "max",
        "tolerance": 0.15
    },
    "jitter": {
        "target_type": "number",
        "direction": "min",
        "tolerance": 0.1
    },
    "throughput": {
        "target_type": "number",
        "direction": "max",
        "tolerance": 0.1
    },
    "connection_uptime": {
        "target_type": "number",
        "direction": "max",
        "tolerance": 0.05
    },
    "error_rate": {
        "target_type": "number",
        "direction": "min",
        "tolerance": 0.05
    },
    "retransmissions": {
        "target_type": "number",
        "direction": "min",
        "tolerance": 0.1
    },

    # --- Categorical traits ---
    "os_type": {
        "target_type": "categorical",
        "mapping": {
            "Linux": 2,
            "Windows": 1,
            "Unknown": 0
        }
    },
    "expansion_trigger": {
        "target_type": "categorical",
        "mapping": {
            "scan_complete": 2,
            "manual_override": 1,
            "none": 0
        }
    },

    # --- Boolean traits ---
    "open_ports": {
        "target_type": "boolean",
        "eval": eval_open_ports
    },
    "blocked_ports": {
        "target_type": "boolean",
        "eval": eval_blocked_ports
    },
    "ips_discovered": {
        "target_type": "boolean",
        "eval": eval_ips_discovered
    }
}

# --- End: Modules/Trait_defs.py ---


# --- Begin: Modules/Traits.py ---

# Queen/Modules/Traits.py

"""
Traits.py
---------
Defines evolutionary trait progression for hive broodlings.
Includes:
- TRAIT_DEFINITIONS: hierarchical trait metadata
- TraitEngine: evaluation and evolution logic
"""



# -------------------------------
# Trait Definitions
# -------------------------------

TRAIT_DEFINITIONS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "adaptability": {
        # --- Tier 1 Base Traits ---
        "network_probe": {
            "tier": 1,
            "evolves_to": "multi_channel_resilience",
            "eval": lambda b, _: len(b.telemetry.get("ip_ranges", []))
        },
        "port_scan": {
            "tier": 1,
            "evolves_to": "low_signature_scan",
            "eval": lambda b, _: len(b.telemetry.get("open_ports", []))
        },
        "protocol_adapt": {
            "tier": 1,
            "evolves_to": "dynamic_protocol_translation",
            "eval": lambda b, _: len(b.telemetry.get("protocols", []))
        },
        "resource_awareness": {
            "tier": 1,
            "evolves_to": "energy_efficiency",
            "eval": lambda b, _: 1 if b.telemetry.get("cpu_pct", 100) <= 50 else 0
        },
        "os_detection": {
            "tier": 1,
            "evolves_to": "environment_mimicry",
            "eval": lambda b, _: 1 if "os_type" in b.telemetry else 0
        },
        "thermal_awareness": {
            "tier": 1,
            "evolves_to": "adaptive_throttling",
            "eval": lambda b, _: 1 if b.telemetry.get("temperature_c", 0) > 0 else 0
        },
        "colony_migration": {
            "tier": 1,
            "evolves_to": "colony_cooperation",
            "eval": lambda b, _: 1 if b.telemetry.get("migration_event", False) else 0
        },
        "role_assignment": {
            "tier": 1,
            "evolves_to": "role_reassignment",
            "eval": lambda b, _: 1 if b.telemetry.get("role", None) is not None else 0
        },
        "stealth_mode": {
            "tier": 1,
            "evolves_to": "signal_masking",
            "eval": lambda b, _: 1 if b.telemetry.get("latency_ms", 999) <= 100 else 0
        },
        "timing_obfuscation": {
            "tier": 1,
            "evolves_to": "temporal_adapt",
            "eval": lambda b, _: 1 if b.telemetry.get("timing_jitter", False) else 0
        },

        # --- Tier 2 Upgrades ---
        "multi_channel_resilience": {
            "tier": 2,
            "evolves_from": "network_probe",
            "eval": lambda b, _: 1 if len(b.telemetry.get("ip_ranges", [])) > 1 else 0
        },
        "low_signature_scan": {
            "tier": 2,
            "evolves_from": "port_scan",
            "eval": lambda b, _: 1 if b.telemetry.get("scan_detected", False) is False else 0
        },
        "dynamic_protocol_translation": {
            "tier": 2,
            "evolves_from": "protocol_adapt",
            "eval": lambda b, _: 1 if len(set(b.telemetry.get("protocols", []))) > 1 else 0
        },
        "energy_efficiency": {
            "tier": 2,
            "evolves_from": "resource_awareness",
            "eval": lambda b, _: 1 if b.telemetry.get("cpu_pct", 100) <= 30 else 0
        },
        "environment_mimicry": {
            "tier": 2,
            "evolves_from": "os_detection",
            "eval": lambda b, _: 1 if b.telemetry.get("os_type") == b.telemetry.get("target_os") else 0
        },
        "adaptive_throttling": {
            "tier": 2,
            "evolves_from": "thermal_awareness",
            "eval": lambda b, _: 1 if b.telemetry.get("temperature_c", 0) < 70 else 0
        },
        "colony_cooperation": {
            "tier": 2,
            "evolves_from": "colony_migration",
            "eval": lambda b, _: 1 if b.telemetry.get("cooperation_event", False) else 0
        },
        "role_reassignment": {
            "tier": 2,
            "evolves_from": "role_assignment",
            "eval": lambda b, _: 1 if b.telemetry.get("role_changed", False) else 0
        },
        "signal_masking": {
            "tier": 2,
            "evolves_from": "stealth_mode",
            "eval": lambda b, _: 1 if b.telemetry.get("signal_detected", False) is False else 0
        },
        "temporal_adapt": {
            "tier": 2,
            "evolves_from": "timing_obfuscation",
            "eval": lambda b, _: 1 if b.telemetry.get("timing_jitter", False) else 0
        },

        # --- Tier 3 Evolutionary ---
        "error_correction_adapt": {
            "tier": 3,
            "evolves_from": "multi_channel_resilience",
            "eval": lambda b, _: 1 if b.telemetry.get("packet_loss", 0) == 0 else 0
        },
        "adaptive_sleep_cycles": {
            "tier": 3,
            "evolves_from": "low_signature_scan",
            "eval": lambda b, _: 1 if b.telemetry.get("idle_cycles", 0) > 0 else 0
        },
        "predictive_adapt": {
            "tier": 3,
            "evolves_from": "dynamic_protocol_translation",
            "eval": lambda b, _: 1 if b.telemetry.get("prediction_success", False) else 0
        },
        "self_healing": {
            "tier": 3,
            "evolves_from": "energy_efficiency",
            "eval": lambda b, _: 1 if b.telemetry.get("errors_recovered", 0) > 0 else 0
        },
        "contextual_decisioning": {
            "tier": 3,
            "evolves_from": "environment_mimicry",
            "eval": lambda b, _: 1 if b.telemetry.get("decision_success", False) else 0
        },
        "latency_compensation": {
            "tier": 3,
            "evolves_from": "adaptive_throttling",
            "eval": lambda b, _: 1 if b.telemetry.get("latency_ms", 999) < 50 else 0
        },
        "collective_learning": {
            "tier": 3,
            "evolves_from": "colony_cooperation",
            "eval": lambda b, _: 1 if b.telemetry.get("knowledge_shared", False) else 0
        },
        "colony_resilience": {
            "tier": 3,
            "evolves_from": "role_reassignment",
            "eval": lambda b, _: 1 if b.telemetry.get("role_recovered", False) else 0
        },
        "adaptive_encryption": {
            "tier": 3,
            "evolves_from": "signal_masking",
            "eval": lambda b, _: 1 if b.telemetry.get("encrypted", False) else 0
        },
        "stealth_evolution": {
            "tier": 3,
            "evolves_from": "temporal_adapt",
            "eval": lambda b, _: 1 if b.telemetry.get("stealth_success", False) else 0
        },

        # --- Tier 4 Lineage ---
        "trait_fusion": {
            "tier": 4,
            "evolves_from": ["protocol_adapt", "resource_awareness"],
            "eval": lambda b, _: 1 if "protocol_adapt" in b.traits and "resource_awareness" in b.traits else 0
        },
        "lineage_memory": {
            "tier": 4,
            "evolves_from": ["colony_cooperation", "trait_fusion"],
            "eval": lambda b, _: 1 if "colony_cooperation" in b.traits and "trait_fusion" in b.traits else 0
        },
        "evolutionary_mutation": {
            "tier": 4,
            "evolves_from": ["self_healing", "predictive_adapt"],
            "eval": lambda b, _: 1 if "self_healing" in b.traits and "predictive_adapt" in b.traits else 0
        }
    }
}

# --- End: Modules/Traits.py ---


# --- Begin: Modules/Snippets/Base_Broodling.py ---


class BroodlingBase:
    """Base broodling; can reference parent queen for permissions and helpers."""
    """
    Base broodling template. The Queen uses this to hatch any broodling type
    (scout, scanner, defender, builder, etc.) by assigning a role and traits.
    """

    def __init__(self, tag, role="scout", traits=None):
        self.tag = tag
        self.role = role
        self.traits = traits or []
        self.telemetry = {}
        self.fitness = 0.0
        self.cycle = 0
        self.fused_traits = None

    def tick(self, **kwargs):
        """
        Generic tick behavior. Specialized broodlings override this.
        Returns (fitness, telemetry).
        """
        return self.fitness, self.telemetry

    def fitness_report(self):
        """Return the latest telemetry for trait evaluation."""
        return self.telemetry

    def apply_trait_flags(self, flags):
        """Apply simple boolean trait flags into telemetry.traits."""
        if not isinstance(flags, (list, tuple)):
            return
        current = set(self.telemetry.get("traits", []))
        current.update(flags)
        self.telemetry["traits"] = list(current)

    def apply_trait_fusion(self, fusion_map):
        """Apply simple fusion mapping: if required traits present, set fused_traits."""
        self.fused_traits = None
        try:
            for reqs, fused in (fusion_map or {}).items():
                needed = set(reqs if isinstance(reqs, (list, tuple)) else [reqs])
                if needed.issubset(set(self.traits or [])):
                    self.fused_traits = fused
                    self.telemetry.setdefault("fused_traits", []).append(fused)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

# --- End: Modules/Snippets/Base_Broodling.py ---


# --- Begin: Hive/Telemetry.py ---



# Mapping between trait names and telemetry report keys
TELEMETRY_KEYS = {
    "latency": "latency_ms",
    "packet_loss": "pkt_loss",
    "bandwidth_efficiency": "net_mbps",
    "jitter": "jitter_ms",
    "throughput": "throughput_mbps",
    "connection_uptime": "uptime_sec",
    "error_rate": "error_pct",
    "retransmissions": "retransmits",
    # Expansion-focused telemetry
    "ips_discovered": "ips_discovered",
    "open_ports": "open_ports",
    "blocked_ports": "blocked_ports",
    "os_type": "os_type",
    "expansion_trigger": "expansion_trigger",
}


def get_value(report, trait_name, default=None):
    """Retrieve telemetry value by trait name, with safe default."""
    key = TELEMETRY_KEYS.get(trait_name)
    return report.get(key, default) if key else default


def scaled_score(value, target, direction="min", tolerance=0.1):
    """
    Compute a scaled score (0–2) based on closeness to target.
    - direction 'min': lower is better
    - direction 'max': higher is better
    - tolerance: fraction of target considered 'close enough'
    """
    if value is None:
        return 0

    if direction == "min":
        if value <= target:
            return 2
        elif value <= target * (1 + tolerance):
            return 1
        else:
            return 0

    elif direction == "max":
        if value >= target:
            return 2
        elif value >= target * (1 - tolerance):
            return 1
        else:
            return 0

    return 0


def categorical_score(value, target, mapping=None):
    """
    Score categorical traits.
    - Exact match to target → 2
    - If mapping provided, use mapping dict for custom scores
    """
    if value is None:
        return 0

    if mapping and value in mapping:
        return mapping[value]

    return 2 if value == target else 0


def score_trait(brood, trait_name, trait_def, target):
    """
    General scoring function for traits.
    Supports numeric, boolean, and categorical trait types.
    """
    value = get_value(brood.fitness_report(), trait_name)

    if trait_def["target_type"] == "number":
        direction = trait_def.get("direction", "min")
        tolerance = trait_def.get("tolerance", 0.1)
        return scaled_score(value, target, direction, tolerance)

    elif trait_def["target_type"] == "boolean":
        return trait_def["eval"](brood, target)

    elif trait_def["target_type"] == "categorical":
        mapping = trait_def.get("mapping")
        return categorical_score(value, target, mapping)

    return 0

# --- End: Hive/Telemetry.py ---


# --- Begin: Hive/Audit.py ---


import json
import os
import shutil

class Audit:
    def __init__(self, root=".", max_log_size=5 * 1024 * 1024):
        """
        :param root: Root directory for logs
        :param max_log_size: Max size in bytes before auto-archiving (default 5 MB)
        """
        self.root = root
        self.log_dir = os.path.join(root, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.max_log_size = max_log_size

        # Centralized log registry
        self.log_paths = {
            "traits": os.path.join(self.log_dir, "traits.log"),
            "fusion": os.path.join(self.log_dir, "fusion.log"),
            "ips": os.path.join(self.log_dir, "ips_checked.log"),
            "ports": os.path.join(self.log_dir, "ports_checked.log"),
            "policy": os.path.join(self.log_dir, "policy.log"),
            "checkpoint": os.path.join(self.log_dir, "checkpoints.log"),
            "queen_state": os.path.join(self.log_dir, "queen_state.log"),
            "errors": os.path.join(self.log_dir, "errors.log"),
            "expansion": os.path.join(self.log_dir, "expansion.log"),
            "replacement": os.path.join(self.log_dir, "replacement.log"),
        }

    def _archive_if_needed(self, path):
        """Archive log if it exceeds max_log_size."""
        if os.path.exists(path) and os.path.getsize(path) >= self.max_log_size:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_name = f"{path}.{timestamp}.archive"
            try:
                shutil.move(path, archive_name)
                logger.info("[Audit] Archived %s → %s", path, archive_name)
            except Exception as e:
                logger.exception("Failed to archive %s: %s", path, e)

    def _write(self, path, entry):
        try:
            self._archive_if_needed(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.exception("Failed to write log entry to %s: %s", path, e)

    def _log(self, category, entry):
        entry["time"] = datetime.utcnow().isoformat()
        path = self.log_paths.get(category)
        if path:
            self._write(path, entry)
        else:
            logger.warning("[Audit] Unknown log category: %s", category)

    def log_trait_activity(self, broodling, trait, message):
        self._log("traits", {
            "broodling": getattr(broodling, "tag", None),
            "trait": trait,
            "message": message
        })

    def log_trait_fusion(self, broodling, fused_trait, source_traits):
        self._log("fusion", {
            "broodling": getattr(broodling, "tag", "queen"),
            "fusion": fused_trait,
            "sources": source_traits
        })

    def log_ip_check(self, broodling, ip_ranges):
        if not isinstance(ip_ranges, (list, tuple)):
            ip_ranges = [str(ip_ranges)]
        self._log("ips", {
            "broodling": getattr(broodling, "tag", None),
            "ip_ranges": ip_ranges
        })

    def log_port_check(self, broodling, open_ports, blocked_ports):
        open_ports = [int(p) for p in open_ports] if isinstance(open_ports, (list, tuple)) else []
        blocked_ports = [int(p) for p in blocked_ports] if isinstance(blocked_ports, (list, tuple)) else []
        self._log("ports", {
            "broodling": getattr(broodling, "tag", None),
            "open_ports": open_ports,
            "blocked_ports": blocked_ports
        })

    def read_logs(self, category):
        """Read back logs for a given category as list of dicts."""
        path = self.log_paths.get(category)
        if not path or not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            print(f"[Audit] Failed to read log {category}: {e}")
            return []

    def log(self, category, entry):
        try:
            self._log(category, entry if isinstance(entry, dict) else {"message": entry})
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

    def log_policy_change(self, message):
        try:
            self._log("policy", {"message": message})
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

    def log_queen_state(self, queen):
        try:
            self._log("queen_state", {"global_cycle": getattr(queen, 'global_cycle', None), "hive_stats": getattr(queen, 'hive_stats', {})})
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass


    def log_error(self, source, message, severity='error'):
        try:
            entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'source': source,
                'severity': severity,
                'message': message
            }
            path = self.log_paths.get('errors', os.path.join(self.log_dir, 'errors.jsonl'))
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
            logger.info('[Audit] Logged %s from %s: %s', severity, source, message)
        except Exception as e:
            logger.exception('Failed to log error: %s', e)

# --- End: Hive/Audit.py ---


# --- Begin: Hive/Fitness.py ---

# Fitness.py

def update_fitness(brood, report, current_score, goal_traits, trait_definitions, score_trait):
    """
    Compute fitness for a broodling based on:
    - survival (cycles lived)
    - exploration success (IPs, ports, protocols)
    - environment awareness (CPU, latency, OS detection)
    - innovation (new traits discovered)
    Returns both the final score and a breakdown dictionary.
    """

    contributions = {
        "survival": 0.0,
        "exploration": 0.0,
        "environment": 0.0,
        "traits": 0.0,
        "innovation": 0.0
    }

    score = current_score

    # Survival contribution
    survival = report.get("cycles", brood.cycle) * 0.1
    contributions["survival"] = survival
    score += survival

    # Exploration contribution
    exploration = (
        len(report.get("ip_ranges", [])) * 1.0 +
        len(report.get("open_ports", [])) * 2.0
    )
    contributions["exploration"] = exploration
    score += exploration

    # Environment awareness contribution
    env_score = 0.0
    if report.get("cpu_pct", 100) <= 50:  # efficient resource use
        env_score += 1.0
    if report.get("latency_ms", 999) <= 100:
        env_score += 1.0
    contributions["environment"] = env_score
    score += env_score

    # Weighted trait alignment contribution
    flat_traits = {
        name: trait_def
        for category, traits in trait_definitions.items()
        for name, trait_def in traits.items()
    }

    trait_score = 0.0
    for trait_name, goal in goal_traits.items():
        trait_def = flat_traits.get(trait_name)
        if trait_def:
            delta = score_trait(brood, trait_name, trait_def, goal["target"])
            weight = trait_def.get("weight", 1.0)
            trait_score += delta * weight
    contributions["traits"] = trait_score
    score += trait_score

    # Innovation bonus
    if report.get("new_trait_discovered", False):
        contributions["innovation"] = 5.0
        score += 5.0

    return score, contributions


class Fitness:
    @staticmethod
    def evaluate(broodlings, cfg, memory):
        """
        Aggregate fitness across broodlings with optional weighting.
        """
        fitness_cfg = cfg.get("fitness", {}) if isinstance(cfg, dict) else {}
        agg_mode = (fitness_cfg.get("aggregation_mode") or "average").lower()
        weighting = fitness_cfg.get("weighting") or {}

        if agg_mode == "weighted":
            total_weight, weighted_sum = 0.0, 0.0
            for b in broodlings:
                role = (getattr(b, "role", "") or "").lower()
                w = float(weighting.get(role, 1.0))
                val = (getattr(b, "fitness", 0) or 0)
                weighted_sum += val * w
                total_weight += w
            avg_fitness = weighted_sum / max(1.0, total_weight)
        else:
            fitness_sum = sum((getattr(b, "fitness", 0) or 0) for b in broodlings)
            avg_fitness = fitness_sum / max(1, len(broodlings))

        role_counts = Counter((getattr(b, "role", "") or "").lower() for b in broodlings)

        return {
            "avg_fitness": avg_fitness,
            "diversity_index": len(set(tuple(getattr(b, "traits", [])) for b in broodlings)),
            "role_distribution": dict(role_counts),
            "lineage_avg_depth": sum(memory.get_age(b) for b in broodlings) / max(1, len(broodlings)),
            "innovation_events": [
                b.tag for b in broodlings if getattr(b, "telemetry", {}).get("new_trait_discovered", False)
            ]
        }

# --- End: Hive/Fitness.py ---


# --- Begin: Hive/Storage.py ---

# Storage.py v2
# ----------------
# Handles checkpointing and restoration of hive state.
# Captures hive stats, fitness landscape, broodling traits, and genetic memory.

import os
import json
import tempfile
import time


class StorageV2:
    def __init__(self, root: str, audit=None, keep_history: bool = True):
        self.root = root
        self.chk_dir = os.path.join(root, "logs")
        os.makedirs(self.chk_dir, exist_ok=True)
        self.audit = audit
        self.keep_history = keep_history

    def _checkpoint_path(self, version: int | None = None) -> str:
        if self.keep_history and version is not None:
            return os.path.join(self.chk_dir, f"checkpoint_{version:04d}.json")
        return os.path.join(self.chk_dir, "checkpoint.json")

    def checkpoint(self, queen):
        # --- Core hive snapshot ---
        snap = {
            "schema_version": "2.2",
            "timestamp": time.time(),
            "global_cycle": queen.global_cycle,
            "stage": queen.stage,
            "stage_cycle_count": queen.stage_cycle_count,
            "hive_population": len(queen.broodlings),
            "avg_fitness": queen.hive_stats.get("avg_fitness", 0.0),
            "diversity_index": queen.hive_stats.get("diversity_index", 0.0),
            "role_distribution": queen.hive_stats.get("role_distribution", {}),
            "lineage_avg_depth": queen.hive_stats.get("lineage_avg_depth", 0.0),
            "last_reset_info": queen.hive_stats.get("last_reset_info"),
            "ips_discovered_total": queen.hive_stats.get("ips_discovered_total", 0),
            "open_ports_total": queen.hive_stats.get("open_ports_total", 0),
            "colonies_spawned": len(getattr(queen, "colonies", [])),
            "innovation_events": queen.hive_stats.get("innovation_events", []),
            # --- Fitness landscape ---
            "fitness_scores": dict(queen.fitness_scores),
            # --- Genetic memory snapshot ---
            "genetic_memory": [
                gm.to_dict() if hasattr(gm, "to_dict") else str(gm)
                for gm in getattr(queen, "genetic_memory", [])
            ],
            # --- Trait distribution ---
            "broodling_traits": []
        }

        # --- Broodling trait evaluation ---
        for b in queen.broodlings:
            trait_eval = {}
            for domain, traits in TRAIT_DEFINITIONS.items():
                for trait_name, trait_def in traits.items():
                    try:
                        trait_eval[trait_name] = trait_def["eval"](b, None)
                    except Exception as e:
                        logger.exception("Unhandled exception: %s", e)
                        trait_eval[trait_name] = None
            snap["broodling_traits"].append({
                "id": getattr(b, "id", None),
                "traits": list(getattr(b, "traits", [])),
                "fitness": getattr(b, "fitness", None),
                "telemetry": getattr(b, "telemetry", {}),
                "trait_eval": trait_eval
            })

        # --- Versioned file write ---
        version = None
        if self.keep_history:
            existing = [f for f in os.listdir(self.chk_dir) if f.startswith("checkpoint_")]
            version = len(existing) + 1

        path = self._checkpoint_path(version)

        try:
            with tempfile.NamedTemporaryFile("w", dir=self.chk_dir, delete=False) as tmp:
                json.dump(snap, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp.name, path)
            if not (os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX")):
                logger.info("Checkpoint saved → %s", path)
        except Exception as e:
            print(f"Failed to save checkpoint: {e}")

        if self.audit:
            self.audit.log("checkpoint", snap)

    def restore(self, version: int | None = None) -> dict:
        """Load a checkpoint snapshot. If version is None, load latest."""
        if version is None and self.keep_history:
            files = sorted([f for f in os.listdir(self.chk_dir) if f.startswith("checkpoint_")])
            if not files:
                raise FileNotFoundError("No checkpoints found")
            path = os.path.join(self.chk_dir, files[-1])
        else:
            path = self._checkpoint_path(version)

        with open(path, "r") as f:
            snap = json.load(f)
        return snap

# --- End: Hive/Storage.py ---


# --- Begin: Modules/Broodlings.py ---


import random
audit = Audit(root='.')


class Scout(BroodlingBase):
    # Real scanning helpers
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
        _HAS_SCAPY = True
    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        _HAS_SCAPY = False

    def _tcp_scan_ports(self, ip, ports, timeout=0.5):
        import socket
        open_ports = []
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                res = s.connect_ex((ip, int(p)))
                s.close()
                if res == 0:
                    open_ports.append(int(p))
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                continue
        return open_ports

    def _arp_discover(self, cidr):
        # Use scapy to discover hosts on the local link when available.
        # If scapy is not present or fails, fall back to a TCP-connect probe across the /24.
        hosts = []
        if getattr(self, '_HAS_SCAPY', False):
            try:
                # suppress verbose
                self.scapy_conf = getattr(self, 'scapy_conf', None)
                from scapy.all import srp, Ether, ARP, conf
                conf.verb = 0
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr), timeout=2, retry=1)
                for _, r in ans:
                    hosts.append(r.psrc)
                return hosts
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                # fall through to TCP-based discovery
                hosts = []

        # Fallback: TCP-based lightweight discovery by attempting connections to common ports.
        # Parse the cidr to derive a /24 prefix (best-effort). This is intentionally conservative.
        try:
            base = str(cidr).split('/')[0]
            parts = base.split('.')
            prefix = '.'.join(parts[0:3])
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            return []

        ips = [f"{prefix}.{i}" for i in range(1, 255)]
        common_ports = [80, 443, 22]
        try:
            import concurrent.futures
            def probe(ip):
                try:
                    openp = self._tcp_scan_ports(ip, common_ports, timeout=0.12)
                    return ip if openp else None
                except Exception as e:
                    logger.exception("Unhandled exception: %s", e)
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as exe:
                futures = {exe.submit(probe, ip): ip for ip in ips}
                for f in concurrent.futures.as_completed(futures, timeout=20):
                    try:
                        res = f.result()
                    except Exception as e:
                        logger.exception("Unhandled exception: %s", e)
                        res = None
                    if res:
                        hosts.append(res)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            # Last-resort: try only the base gateway/start ip
            try:
                gw = f"{prefix}.1"
                if self._tcp_scan_ports(gw, common_ports, timeout=0.12):
                    hosts.append(gw)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass

        return hosts

    def tick(self, ip_range=None, ports=None, real_scan=False, **kwargs):
        # Layered discovery orchestration
        start_ip = None
        if ip_range:
            if isinstance(ip_range, (list, tuple)):
                start_ip = str(ip_range[0])
            else:
                start_ip = str(ip_range)
        start_ip = start_ip or "10.0.0.1"
        try:
            parts = start_ip.split('.')
            prefix = '.'.join(parts[0:3])
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            prefix = '10.0.0'

        # Config-driven parameters
        cfg = getattr(self, 'parent', None) and getattr(self.parent, 'cfg', {}) or {}
        scan_ports = ports or cfg.get('scan_ports', [22, 80, 443, 8080])
        timeout = float(cfg.get('scan_timeout', DEFAULT_SCAN_TIMEOUT))
        use_masscan = bool(cfg.get('use_masscan', False))
        use_nmap = bool(cfg.get('use_nmap', False))
        use_ssdp = bool(cfg.get('use_ssdp', True))
        use_mdns = bool(cfg.get('use_mdns', True))
        use_app_enum = bool(cfg.get('use_app_enum', True))

        found_ips = set()
        ip_open_ports = {}

        use_real = real_scan or self.telemetry.get('real_scan') or ('real_scan' in (self.traits or [])) or cfg.get('enable_real_scan', False)
        if use_real:
            cidr = f"{prefix}.0/24"
            # 1) fast masscan pass if enabled
            if use_masscan:
                try:
                    m = MasscanScanner(timeout=timeout, ports=scan_ports)
                    mc = m.masscan(cidr, scan_ports)
                    for ip, ports_found in mc.items():
                        found_ips.add(ip)
                        ip_open_ports.setdefault(ip, set()).update(ports_found)
                except Exception:
                    logger.exception('Masscan scan failed')
            # 2) ARP discovery / scapy fallback
            try:
                hosts = self._arp_discover(cidr) if getattr(self, '_HAS_SCAPY', False) else []
            except Exception:
                logger.exception('ARP discovery failed')
                hosts = []
            if start_ip and start_ip not in hosts:
                hosts.append(start_ip)

            # 3) TCP connect scans for hosts not already probed
            tcp_scanner = TCPConnectScanner(timeout=timeout, ports=scan_ports)
            try:
                import concurrent.futures
                targets = [h for h in hosts if h not in found_ips]
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(4, len(targets)))) as exe:
                    futures = {exe.submit(tcp_scanner.tcp_scan, h, scan_ports): h for h in targets}
                    for f in concurrent.futures.as_completed(futures, timeout=max(5, int(timeout*20))):
                        h = futures[f]
                        try:
                            openp = f.result()
                        except Exception:
                            logger.exception('TCP scan failed for %s', h)
                            openp = []
                        if openp:
                            found_ips.add(h)
                            ip_open_ports.setdefault(h, set()).update(openp)
            except Exception:
                logger.exception('Concurrent TCP scans failed')
                for h in hosts:
                    try:
                        openp = tcp_scanner.tcp_scan(h, scan_ports)
                        if openp:
                            found_ips.add(h)
                            ip_open_ports.setdefault(h, set()).update(openp)
                    except Exception:
                        pass

            # 4) service enumeration (SSDP/mDNS)
            if use_ssdp:
                try:
                    for addr, resp in ssdp_probe(timeout=timeout):
                        found_ips.add(addr)
                except Exception:
                    logger.exception('SSDP probe failed')
            if use_mdns:
                try:
                    for addr, resp in mdns_probe(timeout=timeout):
                        found_ips.add(addr)
                except Exception:
                    logger.exception('mDNS probe failed')

            # 5) application-level enumeration and banner grabbing
            if use_app_enum:
                for ip in list(found_ips):
                    try:
                        banners = {}
                        if 80 in scan_ports:
                            httpb = grab_http_banner(ip, port=80, timeout=timeout)
                            if httpb:
                                banners['http'] = httpb.splitlines()[0:3]
                        if 443 in scan_ports:
                            cert = grab_tls_cert(ip, port=443, timeout=max(2.0, timeout))
                            if cert:
                                banners['tls_cert_subject'] = cert.get('subject')
                        # ssh banner
                        try:
                            import socket
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1.5)
                            if s.connect_ex((ip, 22)) == 0:
                                try:
                                    b = s.recv(256)
                                    banners['ssh_banner'] = b.decode('utf-8', errors='ignore').strip()
                                except Exception:
                                    pass
                            s.close()
                        except Exception:
                            pass
                        if banners:
                            self.telemetry.setdefault('service_banners', {})[ip] = banners
                    except Exception:
                        logger.exception('App enumeration failed for %s', ip)
        else:
            # simulated discovery
            num_found = random.randint(0, 5)
            for _ in range(num_found):
                last = random.randint(2, 250)
                ip = f"{prefix}.{last}"
                found_ips.add(ip)
                open_ports = [p for p in scan_ports if random.random() < 0.35]
                ip_open_ports[ip] = set(open_ports)

        # finalize telemetry
        self.telemetry['ip_ranges'] = [f"{prefix}.0/24"]
        self.telemetry['found_ips'] = list(found_ips)
        self.telemetry['ip_open_ports'] = {k: list(v) for k, v in ip_open_ports.items()}
        self.telemetry['ips_discovered'] = len(found_ips)
        self.telemetry['open_ports'] = list({p for ports in ip_open_ports.values() for p in ports})
        self.telemetry['blocked_ports'] = []

        # Resource telemetry
        self.telemetry['cpu_pct'] = random.uniform(5, 60)
        self.telemetry['ram_pct'] = random.uniform(5, 60)
        self.telemetry['io_wait'] = random.uniform(0, 30)

        # Environment telemetry
        self.telemetry['latency_ms'] = random.randint(5, 200)
        self.telemetry['os_type'] = random.choice(['linux', 'windows', 'macos'])
        self.telemetry['connected_wifi'] = True

        # Apply trait flags and fusions
        self.apply_trait_flags(['network_probe', 'port_scan'])
        self.apply_trait_fusion({('network_probe', 'stealth_mode'): 'ghost_probe'})

        # Fitness: prefer hosts with services and more open ports
        self.fitness = len(self.telemetry.get('open_ports', [])) * 3 + len(self.telemetry.get('found_ips', []))
        self.cycle += 1

        # Audit logging
        if self.telemetry.get('found_ips'):
            audit.log_trait_activity(self, 'multi_range_probe', f"FoundIPs={self.telemetry.get('found_ips')}")
            try:
                audit.log_ip_check(self, self.telemetry.get('found_ips'))
            except Exception:
                logger.exception('Failed to log ip check')
        if self.telemetry.get('open_ports'):
            audit.log_trait_activity(self, 'port_scan', f"Open={self.telemetry.get('open_ports')}")
            try:
                audit.log_port_check(self, self.telemetry.get('open_ports'), self.telemetry.get('blocked_ports', []))
            except Exception:
                logger.exception('Failed to log port check')
        if self.fused_traits:
            audit.log_trait_fusion(self, self.fused_traits, ['network_probe', 'stealth_mode'])

        # Learning: persist discovered ports to queen genetic memory for future hatches
        try:
            parent = getattr(self, 'parent', None)
            if parent:
                for ip, ports in self.telemetry.get('ip_open_ports', {}).items():
                    for p in ports:
                        t = f'port_{p}'
                        if t not in parent.genetic_memory:
                            parent.genetic_memory.append(t)
        except Exception:
            logger.exception('Failed to update genetic memory')

        return self.fitness, self.telemetry


class Scanner(BroodlingBase):
    def tick(self, ports=None, ip=None, ip_range=None, **kwargs):
        """Scanner: in live environments perform TCP connect scans against a provided IP (best-effort).
        Falls back to simulated sampling when live actions are not allowed or target not provided."""
        scanned_ports = ports or [22, 80, 443]
        open_ports = []
        blocked_ports = []
        found_ips = []
        ip_open_map = {}

        # Live scanning when allowed and a specific IP is provided
        if live_allowed() and ip:
            try:
                scanner = TCPConnectScanner(timeout=DEFAULT_SCAN_TIMEOUT, ports=scanned_ports)
                found = scanner.tcp_scan(ip, scanned_ports)
                open_ports = [int(p) for p in found]
                blocked_ports = [p for p in scanned_ports if p not in open_ports]
                if open_ports:
                    found_ips = [ip]
                    ip_open_map[ip] = open_ports
            except Exception:
                # fallback to simulated behavior on errors
                open_ports = [p for p in scanned_ports if random.random() < 0.3]
                blocked_ports = [p for p in scanned_ports if p not in open_ports]
        else:
            # non-live or no ip target: simulate lightweight scan
            open_ports = [p for p in scanned_ports if random.random() < 0.3]
            blocked_ports = [p for p in scanned_ports if p not in open_ports]

        # store telemetry in a way that other components expect
        self.telemetry["scanned_ports"] = scanned_ports
        self.telemetry["open_ports"] = open_ports
        self.telemetry["blocked_ports"] = blocked_ports
        if found_ips:
            self.telemetry["found_ips"] = found_ips
        if ip_open_map:
            # normalize to simple dict
            self.telemetry["ip_open_ports"] = {k: list(v) for k, v in ip_open_map.items()}

        self.apply_trait_flags(["low_signature_scan"])

        self.fitness = len(open_ports) * 2
        self.cycle += 1

        audit.log_trait_activity(self, "scanner", f"Scanned={scanned_ports}, Open={open_ports}")
        try:
            audit.log_port_check(self, open_ports, blocked_ports)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass
        return self.fitness, self.telemetry


class Defender(BroodlingBase):
    def tick(self, hosts=None, **kwargs):
        """Defender: in live environments perform safe local reachability checks to infer blocked ports.
        Non-live fallback retains simulated behavior."""
        ports_to_check = [22, 80, 443, 3389, 3306]
        blocked_ports = []

        if live_allowed():
            try:
                import socket
                for p in ports_to_check:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.2)
                        target = (hosts[0] if hosts else '127.0.0.1')
                        res = s.connect_ex((target, int(p)))
                        s.close()
                        # connect_ex == 0 means open; non-zero treated as blocked/unreachable here
                        if res != 0:
                            blocked_ports.append(p)
                    except Exception:
                        blocked_ports.append(p)
            except Exception:
                # fallback to simulated
                blocked_ports = random.sample(range(20, 1024), random.randint(0, 5))
        else:
            blocked_ports = random.sample(range(20, 1024), random.randint(0, 5))

        self.telemetry["blocked_ports"] = blocked_ports
        # best-effort resource telemetry
        try:
            self.telemetry["cpu_pct"] = float(self.telemetry.get("cpu_pct", random.uniform(5, 50)))
        except Exception:
            self.telemetry["cpu_pct"] = random.uniform(5, 50)
        try:
            self.telemetry["ram_pct"] = float(self.telemetry.get("ram_pct", random.uniform(5, 50)))
        except Exception:
            self.telemetry["ram_pct"] = random.uniform(5, 50)
        try:
            self.telemetry["io_wait"] = float(self.telemetry.get("io_wait", random.uniform(0, 20)))
        except Exception:
            self.telemetry["io_wait"] = random.uniform(0, 20)

        self.fitness = len(blocked_ports)
        self.cycle += 1

        if "firewall_awareness" in self.traits:
            audit.log_trait_activity(self, "firewall_awareness", f"Blocked={blocked_ports}")

        try:
            audit.log_port_check(self, [], blocked_ports)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        return self.fitness, self.telemetry


class Builder(BroodlingBase):
    def tick(self, **kwargs):
        """Builder: in live environments prefer to materialize useful resources and trigger expansion when colonies exist."""
        resources_built = random.choice(["node", "link", "cache", "relay"])
        expansion = False

        # If running live and attached to a queen with colonies, prefer building relays/caches and trigger expansion
        try:
            if live_allowed() and getattr(self, 'parent', None):
                parent = getattr(self, 'parent')
                # if parent has discovered ips in colonies, build relay to support them
                try:
                    for c in (getattr(parent, 'colonies', []) or []):
                        if c.get('discovered_ips'):
                            resources_built = 'relay'
                            expansion = True
                            break
                except Exception:
                    pass
        except Exception:
            pass

        self.telemetry["resources_built"] = resources_built
        self.telemetry["expansion_trigger"] = expansion or random.choice([True, False])

        self.apply_trait_fusion({
            ("trait_fusion", "builder"): "builder_guard"
        })

        self.fitness = 3 if self.telemetry["expansion_trigger"] else 1
        self.cycle += 1

        audit.log_trait_activity(self, "builder", f"Built={resources_built}, Expansion={self.telemetry['expansion_trigger']}")
        return self.fitness, self.telemetry

# --- End: Modules/Broodlings.py ---


# --- Begin: Memory/QueenMemory.py ---


import json
import os
import itertools

class QueenMemory:
    """
    Adaptive genetic memory and lifecycle manager.
    - Config-driven thresholds and decay
    - Generalized trait inheritance across categories
    - Lifecycle registration, age tracking, retirement automation
    - Trait scoring, promotion, decay, and fusion
    - Error penalties with resilience trait spawning
    - Persistent lineage file with cycle summaries
    """

    def __init__(self, lineage_file="modules/lineage.json", config=None):
        # dedupe/presence cache persisted separately
        self.dedupe_file = os.path.join(os.path.dirname(lineage_file) or '.', 'dedupe.json')
        # load dedupe cache
        self._seen_ips = self._load_seen_ips()

        # Configurable parameters
        self.config = config or {
            "promotion_threshold": 10,
            "decay_rate": 1,
            "fusion_threshold": 3
        }

        # Trait memory
        self.trait_scores = {}        # cumulative scores for all traits
        self.lineage_traits = set()   # promoted traits

        # Lifecycle memory
        self.lineage_age = {}         # brood_tag -> age_cycles
        self.max_cycles = {}          # brood_tag -> max_cycles

        # Global cycle counter
        self.global_cycle = 0

        # Persistent lineage file
        self.lineage_file = lineage_file
        d = os.path.dirname(self.lineage_file)
        if d:
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.lineage_file):
            with open(self.lineage_file, "w") as f:
                json.dump({"traits": {}, "errors": {}, "cycles": []}, f)

    # -------------------------
    # Persistence helpers
    # -------------------------
    def _load(self):
        with open(self.lineage_file, "r") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.lineage_file, "w") as f:
            json.dump(data, f, indent=2)

    # -------------------------
    # Dedupe / seen IPs persistence
    # -------------------------
    def _load_seen_ips(self):
        try:
            if os.path.exists(self.dedupe_file):
                with open(self.dedupe_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_seen_ips(self):
        try:
            d = os.path.dirname(self.dedupe_file)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.dedupe_file, 'w') as f:
                json.dump(self._seen_ips, f, indent=2)
        except Exception:
            logger.exception('Failed to persist dedupe file')

    def add_seen_ip(self, ip, ts=None):
        ts = ts or int(time.time())
        self._seen_ips[ip] = ts
        self._save_seen_ips()

    def is_seen_recent(self, ip, ttl=86400):
        ts = self._seen_ips.get(ip)
        if not ts:
            return False
        return (time.time() - ts) < float(ttl)


    def _append_cycle_summary(self, summary):
        data = self._load()
        data.setdefault("cycles", []).append(summary)
        self._save(data)

    def apply_error_penalties(self, error_snippet_path):
        """
        Adjust lineage traits based on error logs:
        - Increment error counters
        - Reduce fitness scores
        - Spawn resilience traits for critical errors
        """
        if not os.path.exists(error_snippet_path):
            print(f"[QueenMemory] No error snippet found at {error_snippet_path}")
            return

        with open(error_snippet_path, "r") as f:
            entries = json.load(f)

        data = self._load()

        for e in entries:
            sev = e["severity"]
            src = e["source"]

            # track error counts
            data["errors"].setdefault(src, {})
            data["errors"][src][sev] = data["errors"][src].get(sev, 0) + 1

            # ensure trait record exists
            data["traits"].setdefault(src, {"fitness": 100, "resilience": 0})

            # apply penalties
            if sev == "error":
                penalty = 5
            elif sev == "critical":
                penalty = 10
            else:
                penalty = 2

            data["traits"][src]["fitness"] = max(
                0, data["traits"][src]["fitness"] - penalty
            )

            # spawn resilience trait if critical
            if sev == "critical":
                data["traits"][src]["resilience"] += 1
                self.lineage_traits.add("resilience")
                print(f"[QueenMemory] {src} gained resilience trait (+1) due to critical error")

        self._save(data)
        print(f"[QueenMemory] Applied penalties and trait evolution from {len(entries)} error entries")

    # -------------------------
    # Lifecycle management
    # -------------------------
    def register_broodling(self, broodling, max_cycles):
        self.lineage_age[broodling.tag] = 0
        self.max_cycles[broodling.tag] = int(max_cycles)

    def tick_broodling(self, broodling):
        self.lineage_age[broodling.tag] = self.lineage_age.get(broodling.tag, 0) + 1

    def get_age(self, broodling):
        return self.lineage_age.get(broodling.tag, 0)

    def should_retire(self, broodling):
        return self.get_age(broodling) >= self.max_cycles.get(broodling.tag, 0)

    def retire_broodlings(self, broodlings):
        """Return broodlings that should continue (filter out retired)."""
        return [b for b in broodlings if not self.should_retire(b)]

    # -------------------------
    # Trait scoring & lineage
    # -------------------------
    def record_success(self, trait_name, score=1):
        self.trait_scores[trait_name] = self.trait_scores.get(trait_name, 0) + score
        if self.trait_scores[trait_name] >= self.config["promotion_threshold"]:
            self.lineage_traits.add(trait_name)

    def record_failure(self, trait_name):
        self.trait_scores[trait_name] = max(0, self.trait_scores.get(trait_name, 0) - 1)

    def absorb_trait(self, trait, brood_tag=None):
        self.lineage_traits.add(str(trait))

    def inherit_traits(self, broodling):
        existing = set(getattr(broodling, "traits", []))

        # Direct lineage traits
        existing.update(self.lineage_traits)

        # Advanced traits across all categories
        for category, traits in TRAIT_DEFINITIONS.items():
            for trait_name, trait_def in traits.items():
                evolves_from = trait_def.get("evolves_from")
                if not evolves_from:
                    continue
                if isinstance(evolves_from, list):
                    satisfied = all(t in self.lineage_traits for t in evolves_from)
                else:
                    satisfied = evolves_from in self.lineage_traits
                if satisfied:
                    existing.add(trait_name)

        broodling.traits = list(existing)
        return list(existing)

    def absorb_from_broodlings(self, broodlings):
        for b in broodlings:
            for category, traits in TRAIT_DEFINITIONS.items():
                for trait, trait_def in traits.items():
                    if trait in getattr(b, "traits", []):
                        eval_fn = trait_def.get("eval")
                        score = 0
                        if callable(eval_fn):
                            try:
                                score = eval_fn(b, None)
                            except Exception as e:
                                logger.exception("Unhandled exception: %s", e)
                                score = 0
                        self.trait_scores[trait] = self.trait_scores.get(trait, 0) + score

    def promote_lineage(self):
        for trait, score in self.trait_scores.items():
            if score >= self.config["promotion_threshold"]:
                self.lineage_traits.add(trait)

    def decay_traits(self):
        """Gradually reduce scores for unused traits."""
        for trait in list(self.trait_scores.keys()):
            self.trait_scores[trait] = max(
                0, self.trait_scores[trait] - self.config["decay_rate"]
            )

    def fuse_traits(self):
        """Create fusion traits when lineage traits consistently co-occur."""
        combos = itertools.combinations(sorted(self.lineage_traits), 2)
        for a, b in combos:
            fusion_name = f"{a}_{b}_fusion"
            if fusion_name not in self.lineage_traits:
                if self.trait_scores.get(a, 0) >= self.config["fusion_threshold"] and \
                   self.trait_scores.get(b, 0) >= self.config["fusion_threshold"]:
                    self.lineage_traits.add(fusion_name)

    # -------------------------
    # Cycle orchestration
    # -------------------------
    def tick_all(self, broodlings):
        self.global_cycle += 1
        results = {}
        fitnesses = []
        ips_total, ports_total = 0, 0

        broodlings = self.retire_broodlings(broodlings)

        for b in broodlings:
            fitness, report = b.tick()
            results[b.tag] = {"fitness": fitness, "telemetry": report}
            try:
                fitnesses.append(float(fitness))
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                fitnesses.append(0.0)

            if "ip_ranges" in report:
                ips_total += len(report["ip_ranges"])
            if "open_ports" in report:
                ports_total += len(report["open_ports"])

            self.tick_broodling(b)

        avg_fitness = float(sum(fitnesses)) / max(1, len(broodlings))

        summary = {
            "cycle": self.global_cycle,
            "population": len(broodlings),
            "avg_fitness": avg_fitness,
            "ips_discovered_total": ips_total,
            "open_ports_total": ports_total,
            "diversity_index": len(set(tuple(sorted(b.traits)) for b in broodlings)),
            "innovations": len(self.lineage_traits)
        }
        results["_summary"] = summary

        self.absorb_from_broodlings(broodlings)
        self.promote_lineage()
        self.decay_traits()
        self.fuse_traits()
        self._append_cycle_summary(summary)

        return results

    # -------------------------
    # Accessors
    # ----------------

    def get_lineage(self):
        """Return a list of promoted lineage traits."""
        return list(self.lineage_traits)

# --- End: Memory/QueenMemory.py ---


# --- Begin: Policy/Policy.py ---


import json

audit = Audit(root=".")

class GeneticMemory:
    """Richer GeneticMemory used by Policy to record events and maintain simple counters.

    This is intentionally lightweight but provides useful helpers used across Policy methods.
    """
    def __init__(self, max_events: int = 5000):
        self.events = []
        self.max_events = int(max_events)
        self.counters = Counter()

    def record_event(self, name: str, data: dict | None = None):
        entry = {"time": datetime.utcnow().isoformat(), "event": name, "data": data}
        try:
            self.events.append(entry)
            self.counters[name] += 1
            # keep bounded
            if len(self.events) > self.max_events:
                self.events.pop(0)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            # swallow to avoid breaking Policy
            pass

    def to_list(self):
        return list(self.events)

    def recent(self, n: int = 10):
        return list(self.events[-int(n):])

    def count(self, event_name: str):
        return int(self.counters.get(event_name, 0))

    def clear(self):
        self.events.clear()
        self.counters.clear()


class Policy:
    def __init__(self, config=None):
        """
        Initialize Policy with optional config dict.
        """
        self.config = config or {}
        self.default_quotas = {"cpu_pct": 0.5, "mem_mb": 8.0}
        self.current_quotas = dict(self.default_quotas)

        # Startup caps
        startup_caps = self.config.get("startup_caps", {})
        self.startup_caps = {
            "per_broodling": startup_caps.get("per_broodling", self.default_quotas),
            "per_role": startup_caps.get("per_role", {}),
            "hive_total": startup_caps.get("hive_total", {}),
            "gpu": startup_caps.get("gpu", {"enabled": False})
        }

        # Quarantine rules
        self.quarantine = self.config.get("quarantine", {
            "cycles": 3,
            "quotas": {"cpu_pct": 0.3, "mem_mb": 4, "io_kb_min": 50},
            "diagnostic_traits": []
        })

        # Failure rules
        self.failure_rules = self.config.get("failure_rules", {
            "kill_on": [],
            "runaway_thresholds": {"cpu_pct": 5.0, "mem_mb": 64}
        })

        # Logging rules
        self.logging = self.config.get("logging", {
            "segment_max_events": 5000,
            "compress": "gzip",
            "retention_segments": 40,
            "expansion_metrics": []
        })

        # Import rules
        self.imports = self.config.get("imports", {
            "max_bytes": 65536,
            "allow_languages": ["py", "sh", "ps1", "json", "yaml"],
            "validate_syntax": True
        })

        self.telemetry = Telemetry()
        self.fitness = Fitness()
        self.genetic_memory = GeneticMemory()

    def startup_quotas(self):
        return dict(self.startup_caps.get("per_broodling", self.current_quotas))

    def is_runaway(self, telemetry=None, quotas=None):
        telemetry = telemetry or self.telemetry.snapshot()
        quotas = quotas or self.current_quotas
        cpu_ok = telemetry.get("cpu_pct", 0) <= quotas["cpu_pct"]
        mem_ok = telemetry.get("mem_mb", 0) <= quotas["mem_mb"]
        if not cpu_ok and not mem_ok:
            return "cpu+mem"
        elif not cpu_ok:
            return "cpu"
        elif not mem_ok:
            return "mem"
        return None

    def adapt_to_environment(self, telemetry=None):
        telemetry = telemetry or self.telemetry.environment()
        cpu_usage = telemetry.get("avg_cpu_pct", 0.5)
        mem_usage = telemetry.get("avg_mem_mb", 8.0)

        if cpu_usage > 0.7:
            self.current_quotas["cpu_pct"] = max(0.3, self.current_quotas["cpu_pct"] - 0.1)
        else:
            self.current_quotas["cpu_pct"] = min(1.0, self.current_quotas["cpu_pct"] + 0.1)

        if mem_usage > self.current_quotas["mem_mb"]:
            self.current_quotas["mem_mb"] = max(4.0, self.current_quotas["mem_mb"] - 2.0)
        else:
            self.current_quotas["mem_mb"] = min(16.0, self.current_quotas["mem_mb"] + 2.0)

        audit.log_policy_change(
            f"Environment adaptation → CPU {self.current_quotas['cpu_pct']}, MEM {self.current_quotas['mem_mb']}"
        )

    def adjust_for_stage(self, stage):
        stage_map = {
            "juvenile": {"cpu_pct": 0.4, "mem_mb": 6.0},
            "mature": {"cpu_pct": 0.6, "mem_mb": 10.0},
            "elder": {"cpu_pct": 0.8, "mem_mb": 12.0},
            "ascended": {"cpu_pct": 1.0, "mem_mb": 16.0},
        }
        base = stage_map.get(stage, self.default_quotas)
        self.current_quotas["cpu_pct"] = max(base["cpu_pct"], self.current_quotas["cpu_pct"])
        self.current_quotas["mem_mb"] = max(base["mem_mb"], self.current_quotas["mem_mb"])
        audit.log_policy_change(
            f"Stage adjustment ({stage}) → CPU {self.current_quotas['cpu_pct']}, MEM {self.current_quotas['mem_mb']}"
        )

    def enforce_failure_rules(self, telemetry=None):
        telemetry = telemetry or self.telemetry.snapshot()
        kill_on = self.failure_rules.get("kill_on", [])
        thresholds = self.failure_rules.get("runaway_thresholds", {})
        cpu = telemetry.get("cpu_pct", 0)
        mem = telemetry.get("mem_mb", 0)

        for trait in kill_on:
            if trait in telemetry.get("traits", []):
                audit.log_policy_change(f"Failure rule triggered: kill_on trait {trait}")
                self.genetic_memory.record_event("failure", {"trait": trait, "broodling": telemetry.get("id")})
                return "terminate"

        runaway_cpu = cpu > thresholds.get("cpu_pct", float("inf"))
        runaway_mem = mem > thresholds.get("mem_mb", float("inf"))
        if runaway_cpu or runaway_mem:
            audit.log_policy_change(
                f"Runaway detected → CPU {cpu}, MEM {mem} (thresholds {thresholds})"
            )
            self.genetic_memory.record_event("runaway", {"cpu": cpu, "mem": mem, "broodling": telemetry.get("id")})
            return "quarantine"

        if cpu > thresholds.get("cpu_pct", 0) * 0.8 or mem > thresholds.get("mem_mb", 0) * 0.8:
            audit.log_policy_change(f"Warning: approaching runaway → CPU {cpu}, MEM {mem}")
            self.genetic_memory.record_event("warning", {"cpu": cpu, "mem": mem, "broodling": telemetry.get("id")})
            return "warn"

        return None

    def manage_quarantine(self, broodling_id):
        cycles = self.quarantine.get("cycles", 0)
        if cycles <= 0:
            audit.log_policy_change(f"Broodling {broodling_id} terminated after quarantine exhaustion")
            self.genetic_memory.record_event("terminated", {"broodling": broodling_id})
            return "terminate"
        self.quarantine["cycles"] = cycles - 1
        audit.log_policy_change(
            f"Broodling {broodling_id} quarantine cycle decremented → remaining {self.quarantine['cycles']}"
        )
        if self.quarantine["cycles"] == 0:
            audit.log_policy_change(f"Broodling {broodling_id} rehabilitated after quarantine")
            self.genetic_memory.record_event("rehabilitated", {"broodling": broodling_id})
            return "rehabilitate"
        return "quarantine"

    def evaluate_broodling_fitness(self, brood, report, current_score, goal_traits, trait_definitions, score_trait):
        score, contributions = update_fitness(brood, report, current_score, goal_traits, trait_definitions, score_trait)
        audit.log_policy_change(f"Fitness update for {brood.tag} → score {score}, contributions {contributions}")
        self.genetic_memory.record_event("fitness_update", {"broodling": brood.tag, "score": score, "contributions": contributions})
        return score, contributions

    def evaluate_hive_fitness(self, broodlings, cfg, memory):
        results = self.fitness.evaluate(broodlings, cfg, memory)
        audit.log_policy_change(f"Hive fitness evaluation → {results}")
        self.genetic_memory.record_event("hive_fitness", results)
        return results

# --- End: Policy/Policy.py ---


# --- Begin: Queen.py ---

import random
import string
import json
import os



class Queen:
    def __init__(self, config_path="queen_config.json"):
        self.config_path = config_path
        self.cfg = self._load_config(config_path)
        # runtime safety flag: live actions disabled by default
        self.allow_live = bool(self.cfg.get("allow_live_actions", False)) or os.environ.get("ALLOW_LIVE") == "1"
        # propagate to module-level gate so connectors share a single source of truth
        try:
            set_live_allowed(self.allow_live)
        except Exception:
            logger.exception("Failed to set module live flag")
        self.policy = Policy(config=self.cfg)
        self.memory = QueenMemory()
        self.broodlings = []
        self.fitness_scores = {}
        self.colonies = []
        self.genetic_memory = []
        self.audit = Audit(root=".")
        self.storage = StorageV2(root=".", audit=self.audit)
        # transport registry (populated from config flags)
        self.transports = {}
        self._last_conns_signature = None
        try:
            self._init_transports()
        except Exception:
            pass
        try:
            self._start_health_loop()
        except Exception:
            pass

    def _start_health_loop(self):
        """Start a background thread that probes transports' health periodically."""
        try:
            if getattr(self, '_health_thread', None) and getattr(self, '_health_thread').is_alive():
                return
        except Exception:
            pass
        self._health_stop = False
        self._health_thread = threading.Thread(target=self._health_worker, daemon=True)
        self._health_thread.start()

    def _health_worker(self):
        import time
        interval = float(self.cfg.get('transport_health_interval', 2)) if isinstance(self.cfg, dict) else 2.0
        while not getattr(self, '_health_stop', False):
            try:
                for t in list((getattr(self, 'transports', {}) or {}).values()):
                    try:
                        # warm the health cache without blocking dashboard long
                        if hasattr(t, 'health_cached'):
                            t.health_cached(timeout=0.5, ttl=interval)
                        else:
                            # fallback to direct health call
                            try:
                                t.health(timeout=0.5)
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                time.sleep(max(0.5, float(interval)))
            except Exception:
                time.sleep(1.0)

    def _init_transports(self):
        """Initialize transport registry from config connectors block.
        Transports are created but may be unconfigured (host/device None)."""
        cfg = getattr(self, 'cfg', {}) or {}
        conns = cfg.get('connectors', {})
        # SSH
        try:
            ssh_cfg = conns.get('ssh', {}) if conns else {}
            if ssh_cfg.get('enabled'):
                self.transports['ssh'] = SSHConnector(host=ssh_cfg.get('host'), port=ssh_cfg.get('port', 22), user=ssh_cfg.get('user'), key=ssh_cfg.get('key'), password=ssh_cfg.get('password'), allow_live=self.allow_live)
            else:
                self.transports['ssh'] = SSHConnector(host=ssh_cfg.get('host'), port=ssh_cfg.get('port', 22), allow_live=False)
        except Exception:
            pass
        # ADB
        try:
            adb_cfg = conns.get('adb', {}) if conns else {}
            self.transports['adb'] = ADBConnector(device=adb_cfg.get('device'), allow_live=adb_cfg.get('enabled', False))
        except Exception:
            pass
        # SCP
        try:
            scp_cfg = conns.get('scp', {}) if conns else {}
            self.transports['scp'] = SCPConnector(host=scp_cfg.get('host'), port=scp_cfg.get('port', 22), user=scp_cfg.get('user'), key=scp_cfg.get('key'), password=scp_cfg.get('password'), allow_live=scp_cfg.get('enabled', False))
        except Exception:
            pass
        # TCP
        try:
            tcp_cfg = conns.get('tcp', {}) if conns else {}
            self.transports['tcp'] = TCPConnector(host=tcp_cfg.get('host'), port=tcp_cfg.get('port'), allow_live=tcp_cfg.get('enabled', False))
        except Exception:
            pass

        # ensure transport caches are initialised
        try:
            for t in (self.transports or {}).values():
                try:
                    if hasattr(t, 'health_cached'):
                        t.health_cached(timeout=0.1, ttl=1.0)
                except Exception:
                    pass
        except Exception:
            pass
        # Restore last checkpoint state if present to ensure persistence across runs
        try:
            self._restore_state()
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            # non-fatal
            pass

        # Mutation/behavior knobs
        self.base_mutation_prob = 0.15
        self.exploration_burst_prob = 0.25
        self.innovation_bonus = 5.0

        # Queen lifecycle
        self.max_cycles = 300
        self.replacement_cycle = 299

        # Cycle counters
        self.global_cycle = 0
        self.stage = "juvenile"
        self.stage_cycle_count = 0
        self.hive_stats = {}

        self.policy.adjust_for_stage(self.stage)

    def _load_config(self, path):
        try_paths = [path]
        try:
            repo_config = os.path.join(os.path.dirname(__file__), "config", os.path.basename(path))
            try_paths.append(repo_config)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        for p in try_paths:
            try:
                with open(p) as f:
                    return json.load(f)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                continue

        return {
            "cycle_seconds": 30,
            "startup_caps": {"per_broodling": {"cpu_pct": 0.5, "mem_mb": 8}},
            "stage_thresholds": {"juvenile": 50, "mature": 100, "elder": 150},
            "max_hatch_per_cycle": 3,
            "fitness": {"aggregation_mode": "average", "weighting": {}},
            "broodling_lifecycle": 125,
            "target_ip_range": "0.0.0.0/0",
            "allow_live_actions": True,
            "enable_real_scan": True,
            "scheduled": {"enabled": True, "interval_seconds": 600, "rounds": 3, "concurrency": 8, "subnets": ["10.0.0.0/24"]},
            # connector config placeholders
            "connectors": {
                "ssh": {"enabled": False, "host": None, "port": 22},
                "adb": {"enabled": False, "device": None},
                "scp": {"enabled": False, "host": None, "port": 22},
                "tcp": {"enabled": False, "host": None, "port": None}
            },
            # transport health probe interval (seconds)
            "transport_health_interval": 2
        }

    def generate_tag(self):
        return f"BRD-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"

    def _restore_state(self):
        """Load latest checkpoint (if any) and restore genetic memory and last endpoint."""
        try:
            chk_dir = os.path.join('.', 'logs')
            if not os.path.exists(chk_dir):
                return
            files = [f for f in os.listdir(chk_dir) if f.startswith('checkpoint_') and f.endswith('.json')]
            if not files:
                return
            files = sorted(files)
            path = os.path.join(chk_dir, files[-1])
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            # restore genetic memory if present
            gm = data.get('genetic_memory')
            if gm:
                # flatten representations
                self.genetic_memory = [ (g if not isinstance(g, dict) else g.get('name', str(g))) for g in gm ]
            # restore last known hive stats endpoint
            last_ip = None
            colonies = data.get('colonies_spawned')
            if last_ip is None and 'hive_population' in data:
                pass
            # if transports weren't initialized with config-hosts, try to pick targets from checkpoint data
            try:
                # example: if checkpoint contains broodling_traits with ip_open_ports, use one as tcp target
                brood = data.get('broodling_traits') or []
                ip_open_map = {}
                for b in brood:
                    t = b.get('telemetry') or {}
                    for ip, ports in (t.get('ip_open_ports') or {}).items():
                        ip_open_map[ip] = ports
                if ip_open_map:
                    # pick first ip and assign to tcp transport if present
                    first_ip = next(iter(ip_open_map.keys()))
                    if 'tcp' in getattr(self, 'transports', {}):
                        try:
                            self.transports['tcp'].host = first_ip
                            ports = ip_open_map.get(first_ip) or []
                            if ports:
                                self.transports['tcp'].port = ports[0]
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

    def _now(self):
        try:
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            return time.strftime('%Y-%m-%d %H:%M:%S')

    def score_candidates(self, findings: dict):
        """Score candidate hosts found by scans. Returns sorted list of (score, ip, details)."""
        scored = []
        try:
            for ip, ports in (findings or {}).items():
                ports_list = ports if isinstance(ports, (list, tuple)) else list(ports)
                score = 0
                score += len(ports_list) * 2

                # enrich with recent scheduled logs (ports/banners)
                try:
                    logf = os.path.join('.', 'logs', 'scheduled_scans.jsonl')
                    if os.path.exists(logf):
                        with open(logf, 'r') as lf:
                            lines = [l for l in lf if l.strip()]
                            if lines:
                                last = json.loads(lines[-1])
                                findings_last = last.get('findings', {}) or {}
                                if ip in findings_last:
                                    score += 3
                                # support service_banners if present
                                svc = last.get('service_banners') or {}
                                if isinstance(svc, dict) and ip in svc:
                                    score += 4
                except Exception:
                    pass

                # live enrichment: grab HTTP headers and TLS certs (best-effort, non-destructive)
                try:
                    timeout = float(self.cfg.get('scan_timeout', DEFAULT_SCAN_TIMEOUT)) if hasattr(self, 'cfg') else DEFAULT_SCAN_TIMEOUT
                    headers80 = grab_http_headers(ip, port=80, timeout=timeout, use_ssl=False)
                    headers443 = grab_http_headers(ip, port=443, timeout=timeout, use_ssl=True)
                    cert = grab_tls_cert(ip, port=443, timeout=max(2.0, timeout))

                    # HTTP header heuristics
                    for headers in (headers80, headers443):
                        if headers and isinstance(headers, dict) and headers:
                            score += 5
                            srv = headers.get('server')
                            if srv:
                                srv_l = srv.lower()
                                if 'nginx' in srv_l or 'apache' in srv_l or 'gunicorn' in srv_l:
                                    score += 3
                            if 'www-authenticate' in headers:
                                score += 5  # likely admin/login
                            # presence of common security headers increases confidence
                            if headers.get('x-frame-options') or headers.get('content-security-policy'):
                                score += 1

                    # TLS heuristics
                    if cert:
                        score += 6
                        try:
                            san = cert.get('subjectAltName')
                            if san:
                                score += 3
                        except Exception:
                            pass
                        try:
                            notafter = cert.get('notAfter')
                            if notafter:
                                # parse format like 'Jun 10 12:00:00 2026 GMT'
                                from datetime import datetime
                                try:
                                    dt = datetime.strptime(notafter, '%b %d %H:%M:%S %Y %Z')
                                    if dt.timestamp() > time.time():
                                        score += 2
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    logger.exception('Failed to enrich candidate %s', ip)

                scored.append((score, ip, {'ports': ports_list}))
            scored.sort(reverse=True, key=lambda x: x[0])
        except Exception:
            logger.exception('Failed to score candidates')
        return scored

    def safe_delivery_check(self, ip, port=22, username=None, key=None, password=None, timeout=3.0):
        """Non-destructive delivery readiness check.
        - checks port reachability
        - grabs ssh banner
        - if credentials provided and paramiko present, attempts auth+SFTP put/delete
        Returns dict with results and score.
        """
        res = {'ip': ip, 'port': port, 'reachable': False, 'ssh_banner': None, 'auth_ok': False, 'sftp_ok': False, 'score': 0}
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                res['reachable'] = True
                try:
                    b = s.recv(256)
                    res['ssh_banner'] = b.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
            s.close()
        except Exception:
            logger.exception('Delivery reachability check failed for %s', ip)
            return res

        if username and (key or password):
            try:
                import paramiko
                if not (hasattr(paramiko, 'SSHClient')):
                    raise Exception('paramiko missing')
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if key:
                    client.connect(ip, port=port, username=username, key_filename=key, timeout=timeout)
                else:
                    client.connect(ip, port=port, username=username, password=password, timeout=timeout)
                res['auth_ok'] = True
                # try SFTP put/delete small file
                try:
                    sftp = client.open_sftp()
                    tmp = f"/tmp/queen_probe_{int(time.time())}.tmp"
                    with sftp.file(tmp, 'w') as fh:
                        fh.write('probe')
                    sftp.remove(tmp)
                    res['sftp_ok'] = True
                except Exception:
                    logger.exception('SFTP probe failed')
                client.close()
            except Exception:
                logger.exception('Auth probe failed for %s', ip)
        # score heuristics
        try:
            if res['reachable']:
                res['score'] += 5
            if res.get('ssh_banner'):
                res['score'] += 5
            if res['auth_ok']:
                res['score'] += 10
            if res['sftp_ok']:
                res['score'] += 10
        except Exception:
            pass
        return res

    def _log_event(self, tag, msg):
        """Standardized small log line for terminal output."""
        try:
            ts = self._now()
            logger.info("[%s] [%s] %s", ts, tag, msg)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            try:
                logger.info("[%s] %s", tag, msg)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass

        """Load latest checkpoint (if any) and restore genetic memory and last endpoint."""
        try:
            chk_dir = os.path.join('.', 'logs')
            if not os.path.exists(chk_dir):
                return
            files = [f for f in os.listdir(chk_dir) if f.startswith('checkpoint_') and f.endswith('.json')]
            if not files:
                return
            files = sorted(files)
            path = os.path.join(chk_dir, files[-1])
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            # restore genetic memory if present
            gm = data.get('genetic_memory')
            if gm:
                # flatten representations
                self.genetic_memory = [ (g if not isinstance(g, dict) else g.get('name', str(g))) for g in gm ]
            # restore last known hive stats endpoint
            last_ip = None
            colonies = data.get('colonies_spawned')
            if last_ip is None and 'hive_population' in data:
                pass
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

    def hatch_broodling(self, role="scout", traits=None):
        if traits is None:
            traits = self.decide_traits()

        inherited = set(self.memory.get_lineage())
        inherited.update(traits)
        traits = list(inherited)

        r = (role or "").lower()
        if r == "scout":
            b = Scout(tag=self.generate_tag(), role=role, traits=traits)
        elif r == "scanner":
            b = Scanner(tag=self.generate_tag(), role=role, traits=traits)
        elif r == "defender":
            b = Defender(tag=self.generate_tag(), role=role, traits=traits)
        elif r == "builder":
            b = Builder(tag=self.generate_tag(), role=role, traits=traits)
        else:
            b = BroodlingBase(tag=self.generate_tag(), role=role, traits=traits)
        # link broodling back to queen for context and live-action permission
        try:
            b.parent = self
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # Delegate trait inheritance + lifecycle registration to QueenMemory
        self.memory.inherit_traits(b)
        self.memory.register_broodling(b, max_cycles=self.cfg.get("broodling_lifecycle", 125))

        self.broodlings.append(b)
        return b

    def spawn_broodling(self, role="scout"):
        return self.hatch_broodling(role=role, traits=[])

    def decide_traits(self):
        chosen = random.sample(self.genetic_memory, k=min(3, len(self.genetic_memory))) if self.genetic_memory else []
        if random.random() < self.base_mutation_prob:
            chosen.append(random.choice(list(TRAIT_DEFINITIONS.get("adaptability", {}).keys())))
        if not chosen:
            chosen.append("adaptability")
        return chosen

    def expand_colony(self, ip_range):
        scouts = [b for b in self.broodlings if (getattr(b, "role", "") or "").lower() == "scout"]
        discovered = None
        for scout in scouts:
            telemetry = getattr(scout, "telemetry", {})
            if telemetry.get("ips_discovered", 0) > 0 and telemetry.get("open_ports"):
                discovered = telemetry
                break

        if not discovered:
            return None

        new_queen = Queen()
        new_queen.stage = "juvenile"
        # inherit existing genetic memory
        new_queen.genetic_memory = self.genetic_memory.copy()

        # Add travel/connectivity traits
        travel_traits = ["ssh_hop", "adb_tunnel"]
        for trait in travel_traits:
            if trait not in new_queen.genetic_memory:
                new_queen.genetic_memory.append(trait)

        # If telemetry included detailed ips/ports, encode them into genetic memory
        found_ips = discovered.get("found_ips") or []
        ip_open_ports = discovered.get("ip_open_ports") or {}
        for ip, ports in ip_open_ports.items():
            for p in ports:
                t = f"port_{p}"
                if t not in new_queen.genetic_memory:
                    new_queen.genetic_memory.append(t)
        # mark that network probing succeeded
        if found_ips and "network_probe" not in new_queen.genetic_memory:
            new_queen.genetic_memory.append("network_probe")

        # Log a concise spawn message
        try:
            self._log_event("SPAWN", f"Juvenile queen at {ip_range} | discovered={len(found_ips)} ips | inherited_traits={len(new_queen.genetic_memory)}")
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            print(f"Juvenile Queen spawned at {ip_range} with traits: {new_queen.genetic_memory}")

        if self.audit:
            self.audit.log("expansion", {"ip_range": ip_range, "traits": new_queen.genetic_memory, "telemetry": discovered})

        # record discovered ips and open ports with the colony entry
        self.colonies.append({
            "ip_range": ip_range,
            "queen": new_queen,
            "discovered_ips": found_ips,
            "ip_open_ports": ip_open_ports,
        })
        return new_queen

    def run_cycle(self):
        # reload config each cycle so runtime changes via the menu (which writes queen_config.json)
        try:
            if getattr(self, 'config_path', None):
                self.cfg = self._load_config(self.config_path)
            self.allow_live = bool(self.cfg.get('allow_live_actions', False)) or os.environ.get('ALLOW_LIVE') == '1'
            try:
                set_live_allowed(self.allow_live)
            except Exception:
                pass
            # inform policy of updated config
            try:
                if hasattr(self, 'policy') and self.policy:
                    self.policy.config = self.cfg
            except Exception:
                pass
            # refresh transports only when connectors block changed
            try:
                try:
                    new_sig = json.dumps(self.cfg.get('connectors', {}), sort_keys=True)
                except Exception:
                    new_sig = None
                if new_sig != getattr(self, '_last_conns_signature', None):
                    try:
                        self._init_transports()
                        self._last_conns_signature = new_sig
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

        self.global_cycle += 1
        self.stage_cycle_count += 1

        # Stage evolution
        thresholds = self.cfg.get("stage_thresholds", {})
        if self.stage == "juvenile" and self.stage_cycle_count > thresholds.get("juvenile", 50):
            self.stage = "mature"
            self.stage_cycle_count = 0
            self.policy.adjust_for_stage(self.stage)
        elif self.stage == "mature" and self.stage_cycle_count > thresholds.get("mature", 100):
            self.stage = "elder"
            self.stage_cycle_count = 0
            self.policy.adjust_for_stage(self.stage)
        elif self.stage == "elder" and self.stage_cycle_count > thresholds.get("elder", 150):
            self.stage = "ascended"
            self.stage_cycle_count = 0
            self.policy.adjust_for_stage(self.stage)

        # Hatch broodlings
        # Hatch broodlings (favor scouts in early cycles)
        if getattr(self, 'global_cycle', 0) < 10:
            roles = ["scout", "scout", "scout", "scanner", "defender", "builder"]
        else:
            roles = ["scout", "scanner", "defender", "builder"]
        max_hatch = self.cfg.get("max_hatch_per_cycle", 2)
        for _ in range(max_hatch):
            role_choice = random.choice(roles)
            self.hatch_broodling(role=role_choice)

        # Tick broodlings (delegate lifecycle and trait absorption to memory)
        for brood in list(self.broodlings):
            self.memory.tick_broodling(brood)
            brood.tick()
            report = brood.fitness_report()

            if report.get("ips_discovered", 0) > 0:
                self.memory.absorb_trait("network_probe", brood.tag)
            if report.get("open_ports"):
                self.memory.absorb_trait("port_scan", brood.tag)
            if report.get("new_trait_discovered", False):
                self.memory.absorb_trait("innovation", brood.tag)

            if self.memory.should_retire(brood):
                if hasattr(brood, "terminate"):
                    brood.terminate()
                self.broodlings.remove(brood)

        # Fitness aggregation
        fitness_cfg = self.cfg.get("fitness", {}) if isinstance(self.cfg, dict) else {}
        agg_mode = (fitness_cfg.get("aggregation_mode") or "average").lower()
        weighting = fitness_cfg.get("weighting") or {}

        if agg_mode == "weighted":
            total_weight, weighted_sum = 0.0, 0.0
            for b in self.broodlings:
                role = (getattr(b, "role", "") or "").lower()
                w = float(weighting.get(role, 1.0))
                val = (getattr(b, "fitness", 0) or 0)
                weighted_sum += float(val) * w
                total_weight += w
            avg_fitness = float(weighted_sum) / max(1.0, total_weight)
        else:
            fitness_sum = sum((getattr(b, "fitness", 0) or 0) for b in self.broodlings)
            avg_fitness = float(fitness_sum) / max(1, len(self.broodlings))

        # Role distribution via Counter
        role_counts = Counter((getattr(b, "role", "") or "").lower() for b in self.broodlings)

        self.hive_stats = {
            "avg_fitness": avg_fitness,
            "diversity_index": len(set(tuple(getattr(b, "traits", [])) for b in self.broodlings)),
            "role_distribution": dict(role_counts),
            "lineage_avg_depth": sum(self.memory.get_age(b) for b in self.broodlings) / max(1, len(self.broodlings)),
            "last_reset_info": None,
            "ips_discovered_total": sum((getattr(b, "telemetry", {}).get("ips_discovered", 0) or 0) for b in self.broodlings),
            "open_ports_total": sum(
                (len(x) if isinstance(x, (list, tuple)) else (x or 0))
                for x in (getattr(b, "telemetry", {}).get("open_ports", 0) for b in self.broodlings)
            ),
            "innovation_events": [b.tag for b in self.broodlings if getattr(b, "telemetry", {}).get("new_trait_discovered", False)]
        }
        # persist a lightweight live state JSON for watchers (overwritten each cycle)
        try:
            live = {
                'global_cycle': self.global_cycle,
                'broodlings': len(self.broodlings),
                'colonies': len(self.colonies),
                'hive_stats': self.hive_stats
            }
            os.makedirs('./logs', exist_ok=True)
            with open(os.path.join('.', 'logs', 'live_state.json'), 'w', encoding='utf-8') as lf:
                json.dump(live, lf)
        except Exception:
            pass

        # Feed environment telemetry into Policy (cached per-cycle to avoid repeated aggregation)
        try:
            if getattr(self, '_env_cache', None) and self._env_cache.get('cycle') == self.global_cycle:
                env_telemetry = self._env_cache.get('value')
            else:
                if self.broodlings:
                    avg_cpu_pct = sum(b.telemetry.get('cpu_pct', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    avg_mem_mb = sum(b.telemetry.get('mem_mb', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    avg_io_wait = sum(b.telemetry.get('io_wait', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    avg_latency_ms = sum(b.telemetry.get('latency_ms', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    os_distribution = {k: sum(1 for b in self.broodlings if b.telemetry.get('os_type') == k) for k in ("linux", "windows", "macos")}
                else:
                    avg_cpu_pct = 0
                    avg_mem_mb = 0
                    avg_io_wait = 0
                    avg_latency_ms = 0
                    os_distribution = {"linux": 0, "windows": 0, "macos": 0}
                env_telemetry = {
                    'avg_cpu_pct': avg_cpu_pct,
                    'avg_mem_mb': avg_mem_mb,
                    'avg_io_wait': avg_io_wait,
                    'avg_latency_ms': avg_latency_ms,
                    'os_distribution': os_distribution,
                    'hive_size': len(self.broodlings)
                }
                self._env_cache = {'cycle': self.global_cycle, 'value': env_telemetry}
        except Exception:
            env_telemetry = {
                'avg_cpu_pct': 0,
                'avg_mem_mb': 0,
                'avg_io_wait': 0,
                'avg_latency_ms': 0,
                'os_distribution': {"linux": 0, "windows": 0, "macos": 0},
                'hive_size': len(self.broodlings)
            }

        try:
            if hasattr(self, 'policy') and self.policy:
                self.policy.adapt_to_environment(env_telemetry)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # Attempt scout-driven expansion
        try:
            self.expand_colony(ip_range=self.cfg.get("target_ip_range", "0.0.0.0/0"))
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # Successor spawn at 299
        successor = None
        if self.global_cycle == self.replacement_cycle:
            successor = Queen()
            successor.genetic_memory = self.genetic_memory.copy()
            try:
                self._log_event("SPAWN", f"Replacement queen spawned | cycle={self.global_cycle} | inherited_traits={len(successor.genetic_memory)}")
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                print(f"Replacement Queen spawned at cycle {self.global_cycle} with inherited traits: {successor.genetic_memory}")
            if self.audit:
                self.audit.log("replacement", {"cycle": self.global_cycle, "traits": successor.genetic_memory})
            self.colonies.append({"type": "successor", "queen": successor})

        # Graceful retirement at max lifecycle
        if self.global_cycle >= self.max_cycles:
            print("Queen lifecycle complete. Retiring hive.")
            for b in list(self.broodlings):
                if hasattr(b, "terminate"):
                    try:
                        b.terminate()
                    except Exception as e:
                        logger.exception("Unhandled exception: %s", e)
                        pass
                self.broodlings.remove(b)
            try:
                if self.storage:
                    self.storage.checkpoint(self)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass
            try:
                if self.audit:
                    self.audit.log_queen_state(self)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass
            return successor

        # Save checkpoint + audit periodically (throttled)
        try:
            checkpoint_interval = int(self.cfg.get('checkpoint_interval', 5)) if isinstance(self.cfg, dict) else 5
            if checkpoint_interval <= 0 or (self.global_cycle % checkpoint_interval) == 0:
                if self.storage:
                    self.storage.checkpoint(self)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass
        try:
            checkpoint_interval = int(self.cfg.get('checkpoint_interval', 5)) if isinstance(self.cfg, dict) else 5
            if checkpoint_interval <= 0 or (self.global_cycle % checkpoint_interval) == 0:
                if self.audit:
                    self.audit.log_queen_state(self)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # refresh transport health caches in background (best-effort non-blocking)
        try:
            for t in (getattr(self, 'transports', {}) or {}).values():
                try:
                    # call cached health to prime the cache without blocking dashboard
                    _ = t.health_cached(timeout=0.5, ttl=2.0) if hasattr(t, 'health_cached') else None
                except Exception:
                    pass
        except Exception:
            pass

        # concise status line
        try:
            avg_fit = self.hive_stats.get('avg_fitness') if isinstance(self.hive_stats, dict) else None
            self._log_event("CYCLE", f"{self.global_cycle} | broodlings={len(self.broodlings)} | colonies={len(self.colonies)} | avg_fit={avg_fit if avg_fit is not None else 'N/A'}")
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            print(f"Cycle {self.global_cycle} complete → {len(self.broodlings)} broodlings active")
        return successor

    def _load_scheduled_scan_results(self, entries=1):
        """Read scheduled_scans.jsonl and return fused ScanResult dicts for the last `entries` records."""
        try:
            path = os.path.join('.', 'logs', 'scheduled_scans.jsonl')
            if not os.path.exists(path):
                return []
            with open(path, 'r', encoding='utf-8') as f:
                lines = [l for l in f if l.strip()]
            if not lines:
                return []
            lines = lines[-entries:]
            all_results = []
            for ln in lines:
                try:
                    j = json.loads(ln)
                except Exception:
                    continue
                findings = j.get('findings') or {}
                # convert findings ip->ports to ScanResult list
                results = []
                for ip, ports in findings.items():
                    try:
                        conf = min(1.0, 0.2 + 0.1 * len(ports))
                        sr = ScanResult(ip=ip, open_ports=sorted(list(ports or [])), protocols=['tcp'] if ports else [], banners={}, source='scheduled', confidence=conf)
                        results.append(sr)
                    except Exception:
                        pass
                fused = ScanFusion.fuse(results)
                all_results.extend(fused)
            # fuse across entries
            final = ScanFusion.fuse(all_results)
            return [r.to_dict() for r in final]
        except Exception:
            return []

        # Stage evolution
        thresholds = self.cfg.get("stage_thresholds", {})
        if self.stage == "juvenile" and self.stage_cycle_count > thresholds.get("juvenile", 50):
            self.stage = "mature"
            self.stage_cycle_count = 0
            self.policy.adjust_for_stage(self.stage)
        elif self.stage == "mature" and self.stage_cycle_count > thresholds.get("mature", 100):
            self.stage = "elder"
            self.stage_cycle_count = 0
            self.policy.adjust_for_stage(self.stage)
        elif self.stage == "elder" and self.stage_cycle_count > thresholds.get("elder", 150):
            self.stage = "ascended"
            self.stage_cycle_count = 0
            self.policy.adjust_for_stage(self.stage)

        # Hatch broodlings
        # Hatch broodlings (favor scouts in early cycles)
        if getattr(self, 'global_cycle', 0) < 10:
            roles = ["scout", "scout", "scout", "scanner", "defender", "builder"]
        else:
            roles = ["scout", "scanner", "defender", "builder"]
        max_hatch = self.cfg.get("max_hatch_per_cycle", 2)
        for _ in range(max_hatch):
            role_choice = random.choice(roles)
            self.hatch_broodling(role=role_choice)

        # Tick broodlings (delegate lifecycle and trait absorption to memory)
        for brood in list(self.broodlings):
            self.memory.tick_broodling(brood)
            brood.tick()
            report = brood.fitness_report()

            if report.get("ips_discovered", 0) > 0:
                self.memory.absorb_trait("network_probe", brood.tag)
            if report.get("open_ports"):
                self.memory.absorb_trait("port_scan", brood.tag)
            if report.get("new_trait_discovered", False):
                self.memory.absorb_trait("innovation", brood.tag)

            if self.memory.should_retire(brood):
                if hasattr(brood, "terminate"):
                    brood.terminate()
                self.broodlings.remove(brood)

        # Fitness aggregation
        fitness_cfg = self.cfg.get("fitness", {}) if isinstance(self.cfg, dict) else {}
        agg_mode = (fitness_cfg.get("aggregation_mode") or "average").lower()
        weighting = fitness_cfg.get("weighting") or {}

        if agg_mode == "weighted":
            total_weight, weighted_sum = 0.0, 0.0
            for b in self.broodlings:
                role = (getattr(b, "role", "") or "").lower()
                w = float(weighting.get(role, 1.0))
                val = (getattr(b, "fitness", 0) or 0)
                weighted_sum += float(val) * w
                total_weight += w
            avg_fitness = float(weighted_sum) / max(1.0, total_weight)
        else:
            fitness_sum = sum((getattr(b, "fitness", 0) or 0) for b in self.broodlings)
            avg_fitness = float(fitness_sum) / max(1, len(self.broodlings))

        # Role distribution via Counter
        role_counts = Counter((getattr(b, "role", "") or "").lower() for b in self.broodlings)

        self.hive_stats = {
            "avg_fitness": avg_fitness,
            "diversity_index": len(set(tuple(getattr(b, "traits", [])) for b in self.broodlings)),
            "role_distribution": dict(role_counts),
            "lineage_avg_depth": sum(self.memory.get_age(b) for b in self.broodlings) / max(1, len(self.broodlings)),
            "last_reset_info": None,
            "ips_discovered_total": sum((getattr(b, "telemetry", {}).get("ips_discovered", 0) or 0) for b in self.broodlings),
            "open_ports_total": sum(
                (len(x) if isinstance(x, (list, tuple)) else (x or 0))
                for x in (getattr(b, "telemetry", {}).get("open_ports", 0) for b in self.broodlings)
            ),
            "innovation_events": [b.tag for b in self.broodlings if getattr(b, "telemetry", {}).get("new_trait_discovered", False)]
        }
        # persist a lightweight live state JSON for watchers (overwritten each cycle)
        try:
            live = {
                'global_cycle': self.global_cycle,
                'broodlings': len(self.broodlings),
                'colonies': len(self.colonies),
                'hive_stats': self.hive_stats
            }
            os.makedirs('./logs', exist_ok=True)
            with open(os.path.join('.', 'logs', 'live_state.json'), 'w', encoding='utf-8') as lf:
                json.dump(live, lf)
        except Exception:
            pass

        # Feed environment telemetry into Policy (cached per-cycle to avoid repeated aggregation)
        try:
            if getattr(self, '_env_cache', None) and self._env_cache.get('cycle') == self.global_cycle:
                env_telemetry = self._env_cache.get('value')
            else:
                if self.broodlings:
                    avg_cpu_pct = sum(b.telemetry.get('cpu_pct', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    avg_mem_mb = sum(b.telemetry.get('mem_mb', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    avg_io_wait = sum(b.telemetry.get('io_wait', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    avg_latency_ms = sum(b.telemetry.get('latency_ms', 0) for b in self.broodlings) / max(1, len(self.broodlings))
                    os_distribution = {k: sum(1 for b in self.broodlings if b.telemetry.get('os_type') == k) for k in ("linux", "windows", "macos")}
                else:
                    avg_cpu_pct = 0
                    avg_mem_mb = 0
                    avg_io_wait = 0
                    avg_latency_ms = 0
                    os_distribution = {"linux": 0, "windows": 0, "macos": 0}
                env_telemetry = {
                    'avg_cpu_pct': avg_cpu_pct,
                    'avg_mem_mb': avg_mem_mb,
                    'avg_io_wait': avg_io_wait,
                    'avg_latency_ms': avg_latency_ms,
                    'os_distribution': os_distribution,
                    'hive_size': len(self.broodlings)
                }
                self._env_cache = {'cycle': self.global_cycle, 'value': env_telemetry}
        except Exception:
            env_telemetry = {
                'avg_cpu_pct': 0,
                'avg_mem_mb': 0,
                'avg_io_wait': 0,
                'avg_latency_ms': 0,
                'os_distribution': {"linux": 0, "windows": 0, "macos": 0},
                'hive_size': len(self.broodlings)
            }

        try:
            if hasattr(self, 'policy') and self.policy:
                self.policy.adapt_to_environment(env_telemetry)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # Attempt scout-driven expansion
        try:
            self.expand_colony(ip_range=self.cfg.get("target_ip_range", "0.0.0.0/0"))
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # Successor spawn at 299
        successor = None
        if self.global_cycle == self.replacement_cycle:
            successor = Queen()
            successor.genetic_memory = self.genetic_memory.copy()
            try:
                self._log_event("SPAWN", f"Replacement queen spawned | cycle={self.global_cycle} | inherited_traits={len(successor.genetic_memory)}")
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                print(f"Replacement Queen spawned at cycle {self.global_cycle} with inherited traits: {successor.genetic_memory}")
            if self.audit:
                self.audit.log("replacement", {"cycle": self.global_cycle, "traits": successor.genetic_memory})
            self.colonies.append({"type": "successor", "queen": successor})

        # Graceful retirement at max lifecycle
        if self.global_cycle >= self.max_cycles:
            print("Queen lifecycle complete. Retiring hive.")
            for b in list(self.broodlings):
                if hasattr(b, "terminate"):
                    try:
                        b.terminate()
                    except Exception as e:
                        logger.exception("Unhandled exception: %s", e)
                        pass
                self.broodlings.remove(b)
            try:
                if self.storage:
                    self.storage.checkpoint(self)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass
            try:
                if self.audit:
                    self.audit.log_queen_state(self)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass
            return successor

        # Save checkpoint + audit periodically (throttled)
        try:
            checkpoint_interval = int(self.cfg.get('checkpoint_interval', 5)) if isinstance(self.cfg, dict) else 5
            if checkpoint_interval <= 0 or (self.global_cycle % checkpoint_interval) == 0:
                if self.storage:
                    self.storage.checkpoint(self)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass
        try:
            checkpoint_interval = int(self.cfg.get('checkpoint_interval', 5)) if isinstance(self.cfg, dict) else 5
            if checkpoint_interval <= 0 or (self.global_cycle % checkpoint_interval) == 0:
                if self.audit:
                    self.audit.log_queen_state(self)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            pass

        # refresh transport health caches in background (best-effort non-blocking)
        try:
            for t in (getattr(self, 'transports', {}) or {}).values():
                try:
                    # call cached health to prime the cache without blocking dashboard
                    _ = t.health_cached(timeout=0.5, ttl=2.0) if hasattr(t, 'health_cached') else None
                except Exception:
                    pass
        except Exception:
            pass

        # concise status line
        try:
            avg_fit = self.hive_stats.get('avg_fitness') if isinstance(self.hive_stats, dict) else None
            self._log_event("CYCLE", f"{self.global_cycle} | broodlings={len(self.broodlings)} | colonies={len(self.colonies)} | avg_fit={avg_fit if avg_fit is not None else 'N/A'}")
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            print(f"Cycle {self.global_cycle} complete → {len(self.broodlings)} broodlings active")
        return successor

    def print_dashboard(self, max_entries: int = 50, show_more: bool = True):
        """Render a compact stylized dashboard showing real runtime data and only actual scanned IPs/ports.
        When show_more is True include broodling role counts to support --watch monitoring."""
        try:
            # Header with run time and cycle
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print("QUEEN // DASHBOARD")
            print("──────────────────────────────────────────────────────────────")
            print(f" Run time: {now}    Cycle: {getattr(self, 'global_cycle', 'N/A')}\n")

            # SYSTEM
            # Gather system metrics from broodlings/hive_stats as best-effort
            try:
                cpu = None
                if isinstance(self.hive_stats, dict) and 'avg_fitness' in self.hive_stats:
                    cpu = None
            except Exception:
                cpu = None

            try:
                cpu_vals = [b.telemetry.get('cpu_pct') for b in self.broodlings if b.telemetry.get('cpu_pct') is not None]
                cpu = int(round(sum(cpu_vals) / max(1, len(cpu_vals)))) if cpu_vals else None
            except Exception:
                cpu = None
            try:
                mem_vals = [b.telemetry.get('mem_pct') for b in self.broodlings if b.telemetry.get('mem_pct') is not None]
                mem = int(round(sum(mem_vals) / max(1, len(mem_vals)))) if mem_vals else None
            except Exception:
                mem = None
            try:
                lat_vals = [b.telemetry.get('latency_ms') for b in self.broodlings if b.telemetry.get('latency_ms') is not None]
                net = float(sum(lat_vals) / max(1, len(lat_vals))) if lat_vals else None
            except Exception:
                net = None
            try:
                temps = [b.telemetry.get('temperature_c') for b in self.broodlings if b.telemetry.get('temperature_c') is not None]
                temp = int(round(sum(temps) / max(1, len(temps)))) if temps else None
            except Exception:
                temp = None

            cpu_str = f"{cpu}%" if cpu is not None else ""
            mem_str = f"{mem}%" if mem is not None else ""
            net_str = f"{net:.1f} ms" if (net is not None) else ""
            temp_str = f"{temp}°C" if (temp is not None) else ""

            sys_parts = []
            if cpu_str:
                sys_parts.append(f"CPU: {cpu_str}")
            if mem_str:
                sys_parts.append(f"MEM: {mem_str}")
            if net_str:
                sys_parts.append(f"NET: {net_str}")
            if temp_str:
                sys_parts.append(f"TEMP: {temp_str}")

            print("\n SYSTEM")
            if sys_parts:
                print("   " + "     ".join(sys_parts) + "\n")
            else:
                print("   (no system telemetry available)\n")

            # BROODLINGS (show role counts when show_more is True)
            if show_more:
                try:
                    # Prefer live broodling role counts; fall back to hive_stats.role_distribution from checkpoint
                    role_counts = None
                    try:
                        from collections import Counter
                        role_counts = Counter((getattr(b, 'role', '') or '').lower() for b in self.broodlings) if self.broodlings else None
                    except Exception:
                        role_counts = None
                    if (not role_counts or sum(role_counts.values()) == 0) and isinstance(self.hive_stats, dict):
                        rd = self.hive_stats.get('role_distribution') or {}
                        # normalize keys to lowercase
                        role_counts = {k.lower(): v for k, v in rd.items()} if rd else {}
                    if role_counts:
                        if isinstance(role_counts, dict):
                            items = sorted(role_counts.items())
                        else:
                            items = sorted(((r, role_counts[r]) for r in role_counts))
                        counts = '  '.join(f"{role}: {count}" for role, count in items)
                        print(" BROODLINGS")
                        print(f"   {counts}\n")
                    else:
                        print(" BROODLINGS")
                        print("   (no broodlings active)\n")
                except Exception:
                    print(" BROODLINGS")
                    print("   (unable to compute broodling counts)\n")

            # DISCOVERY — aggregate only real scanned ports and IPs
            ports_set = set()
            ips = []
            # Scan layers: load last scheduled_scan entries and fuse into ScanResults
            try:
                scan_layers = self._load_scheduled_scan_results(entries=1)
            except Exception:
                scan_layers = []
            try:
                for b in self.broodlings:
                    for p in (b.telemetry.get('open_ports') or []):
                        try:
                            ports_set.add(int(p))
                        except Exception:
                            pass
                    for ip in (b.telemetry.get('found_ips') or []):
                        if ip not in ips:
                            ips.append(ip)
                for c in self.colonies:
                    ip_open = c.get('ip_open_ports') or {}
                    for ip, ports in ip_open.items():
                        if ip and ip not in ips:
                            ips.append(ip)
                        for p in (ports or []):
                            try:
                                ports_set.add(int(p))
                            except Exception:
                                pass
                    for ip in (c.get('discovered_ips') or []):
                        if ip and ip not in ips:
                            ips.append(ip)
            except Exception:
                pass

            ports_list = sorted(list(ports_set)) if ports_set else []

            print(" DISCOVERY")
            if ports_list:
                print("   Ports: " + "  ".join(str(p) for p in ports_list))
            else:
                print("   Ports:")
            if ips:
                print("   IPs:   " + "  ".join(str(ip) for ip in ips) + "\n")
            else:
                print("   IPs:\n")

            # SCAN LAYERS — show fused recent scan results
            try:
                if scan_layers:
                    print(" SCAN LAYERS")
                    for sr in scan_layers:
                        try:
                            print(f"   {sr['ip']}: ports={sr.get('open_ports', [])} conf={sr.get('confidence',0):.2f} src={sr.get('source')}")
                        except Exception:
                            print(f"   {sr.get('ip')}: {sr}")
                    print("")
            except Exception:
                pass

            # TRANSPORTS — unified transport health overview
            try:
                print(" TRANSPORTS")
                if getattr(self, 'transports', None):
                    for name, t in sorted(self.transports.items()):
                        try:
                            health = t.health(timeout=0.5) if hasattr(t, 'health') else {"name": name, "status": "unknown", "detail": None}
                        except Exception as e:
                            health = {"name": name, "status": "error", "detail": str(e)}
                        status = health.get('status')
                        detail = health.get('detail') or ''
                        print(f"   {name}: {status}" + (f" — {detail}" if detail else ""))
                else:
                    print("   (no transports configured)")
            except Exception:
                print("   (failed to evaluate transports)")

            # TRAITS — show current notable trait mappings; only display if traits exist in genetic_memory
            trait_pairs = [
                ("network_probe", "multi_channel_resilience"),
                ("port_scan", "low_signature_scan"),
                ("os_detection", "environment_mimicry"),
                ("stealth_mode", "signal_masking"),
            ]
            gm = getattr(self, 'genetic_memory', []) or []
            show_traits = any(a in gm or b in gm for a, b in trait_pairs)

            print(" TRAITS")
            if show_traits:
                for a, b in trait_pairs:
                    if a in gm or b in gm:
                        print(f"   {a} → {b}")
            else:
                print("   (no trait discoveries yet)")
            print("")

            # TRAIT HEAT — prevalence of known traits across broodlings
            try:
                if 'TRAIT_ENGINE' in globals():
                    heat = TRAIT_ENGINE.heat_summary(self.broodlings, top_n=6)
                    if heat:
                        print(" TRAIT HEAT")
                        for tname, count, pct in heat:
                            print(f"   {tname}: {count} ({pct*100:.0f}%)")
                        print("")
            except Exception:
                pass

            # STATUS
            last_event = None
            try:
                evs = self.hive_stats.get('innovation_events') if isinstance(self.hive_stats, dict) else []
                if evs:
                    last_event = evs[-1]
            except Exception:
                last_event = None

            try:
                interval = int(self.cfg.get('cycle_seconds', DEFAULT_SCHEDULE_INTERVAL)) if hasattr(self, 'cfg') else DEFAULT_SCHEDULE_INTERVAL
                mins = (interval // 60)
                secs = (interval % 60)
                next_scan = f"{mins}m {secs}s" if mins else f"{secs}s"
            except Exception:
                next_scan = ''

            print(" STATUS")
            print(f"   Last event: {last_event if last_event else '(none)'}")
            print(f"   Next scan:  {next_scan if next_scan else '(unknown)'}\n")

        except Exception as e:
            logger.exception("Unhandled exception while rendering dashboard: %s", e)
            print('Failed to render dashboard')

# --- End: Queen.py ---


# --- Begin: Modules/Dashboard.py ---


import time
import logging
import json
import os

def load_config(config_path="queen_config.json"):
    """Load config JSON, return dict with defaults if missing."""
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return json.load(f)
    return {"cycle_seconds": 30, "use_logging": False, "connectors": {}}


# Trait engine to bridge telemetry scoring and evolutionary definitions
class TraitEngine:
    def __init__(self, telemetry_defs=None, evolution_defs=None):
        self.telemetry_defs = telemetry_defs or {}
        self.evolution_defs = evolution_defs or {}
        # flatten evolution trait names
        self.flattened = []
        for domain, traits in (self.evolution_defs.items() if isinstance(self.evolution_defs, dict) else []):
            try:
                for name in traits.keys():
                    self.flattened.append(name)
            except Exception:
                pass

    def heat_summary(self, broodlings, top_n=5):
        """Return top_n traits by prevalence across broodlings as list of (name,count,prevalence).
        Prevalence measured by presence in broodling.traits or telemetry.traits or boolean eval returning non-zero.
        """
        from collections import Counter
        c = Counter()
        total = max(1, len(broodlings))
        for b in broodlings:
            # explicit trait list
            for t in (getattr(b, 'traits', []) or []):
                c[t] += 1
            # telemetry traits
            for t in ((b.telemetry.get('traits') or []) if isinstance(getattr(b, 'telemetry', {}), dict) else []):
                c[t] += 1
            # evaluate boolean telemetry defs if present
            for tname, tdef in (self.telemetry_defs.items() if isinstance(self.telemetry_defs, dict) else []):
                try:
                    if tdef.get('target_type') == 'boolean' and 'eval' in tdef:
                        val = tdef['eval'](b, None)
                        if val:
                            c[tname] += 1
                except Exception:
                    pass
        if not c:
            return []
        items = c.most_common(top_n)
        return [(name, count, count / float(total)) for name, count in items]


# instantiate a global trait engine for dashboards and policy
try:
    TRAIT_ENGINE = TraitEngine(telemetry_defs=TRAIT_DEFS if 'TRAIT_DEFS' in globals() else {}, evolution_defs=TRAIT_DEFINITIONS if 'TRAIT_DEFINITIONS' in globals() else {})
except Exception:
    TRAIT_ENGINE = None


# --- Credential store: encrypted key vault (local only) ---
class CredentialStore:
    def __init__(self, path=None):
        self.path = os.path.expanduser(path or '~/.queen_creds.json')

    def _save(self, data):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            return True
        except Exception:
            return False

    def _load(self):
        try:
            if not os.path.exists(self.path):
                return {}
            with open(self.path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _derive_key(self, passphrase, salt):
        """Derive a Fernet key from passphrase and salt. Requires cryptography package."""
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            import base64
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
            key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))
            return key
        except Exception:
            return None

    def save_key(self, label, raw_bytes, passphrase):
        try:
            try:
                from cryptography.fernet import Fernet
                has_crypto = True
            except Exception:
                has_crypto = False
            if not has_crypto:
                return False, 'cryptography package required (pip install cryptography)'
            import os, base64
            salt = os.urandom(16)
            key = self._derive_key(passphrase, salt)
            if not key:
                return False, 'KDF failed'
            from cryptography.fernet import Fernet
            f = Fernet(key)
            token = f.encrypt(raw_bytes)
            store = self._load()
            store.setdefault('keys', {})
            store['keys'][label] = {'token': base64.b64encode(token).decode('utf-8'), 'salt': base64.b64encode(salt).decode('utf-8')}
            ok = self._save(store)
            return (ok, 'saved' if ok else 'failed to write store')
        except Exception as e:
            return False, str(e)

    def retrieve_key_one_time(self, label, passphrase):
        try:
            try:
                from cryptography.fernet import Fernet
                has_crypto = True
            except Exception:
                has_crypto = False
            if not has_crypto:
                return False, 'cryptography package required (pip install cryptography)', None
            import base64
            store = self._load()
            keys = store.get('keys') or {}
            ent = keys.get(label)
            if not ent:
                return False, 'label not found', None
            token = base64.b64decode(ent.get('token'))
            salt = base64.b64decode(ent.get('salt'))
            key = self._derive_key(passphrase, salt)
            if not key:
                return False, 'KDF failed', None
            from cryptography.fernet import Fernet
            f = Fernet(key)
            raw = f.decrypt(token)
            # remove entry (one-time)
            try:
                del store['keys'][label]
                self._save(store)
            except Exception:
                pass
            return True, 'ok', raw
        except Exception as e:
            return False, str(e), None


def setup_logging():
    """Configure logging once."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )


def render_dashboard(summary, verbose=False, use_logging=False):
    """
    Render a Hive Dashboard from the summary dict returned by Queen.tick_all().
    By default shows compact metrics. If verbose=True, also lists each broodling.
    If use_logging=True, outputs via logging instead of print.
    """
    if "_summary" not in summary:
        msg = "⚠️ No summary available."
        logging.warning(msg) if use_logging else print(msg)
        return

    s = summary["_summary"]

    lines = []
    lines.append("\n=== 🐝 Hive Dashboard ===")
    lines.append(f"Cycle: {s.get('cycle', '?')}")
    if "stage" in s:
        lines.append(f"Stage: {s.get('stage')} ({s.get('stage_cycle_count', 0)} cycles in stage)")
    lines.append(f"Population: {s.get('population', 0)}")
    lines.append(f"Average Fitness: {s.get('avg_fitness', 0):.2f}")
    lines.append(f"Diversity Index: {s.get('diversity_index', 0)}")

    # Role distribution
    if "role_distribution" in s and s["role_distribution"]:
        roles = ", ".join(f"{role}={count}" for role, count in s["role_distribution"].items())
        lines.append(f"Role Distribution: {roles}")

    # Lineage depth
    if "lineage_avg_depth" in s:
        lines.append(f"Lineage Avg Depth: {s.get('lineage_avg_depth', 0)}")

    lines.append(f"IPs Discovered: {s.get('ips_discovered_total', 0)}")
    lines.append(f"Open Ports: {s.get('open_ports_total', 0)}")
    lines.append(f"Genetic Memory Size: {s.get('genetic_memory_size', 0)}")
    lines.append(f"Colonies Spawned: {s.get('colonies_spawned', 0)}")

    # Innovation events
    if "innovation_events" in s:
        if s["innovation_events"]:
            lines.append(f"Innovation Events: {len(s['innovation_events'])}")
        else:
            lines.append("Innovation Events: none")

    lines.append("=========================\n")

    if verbose:
        lines.append("Broodling Reports:")
        for tag, data in summary.items():
            if tag == "_summary":
                continue
            lines.append(
                f" - {tag}: fitness={data.get('fitness', '?')}, "
                f"traits={data.get('telemetry', {}).get('traits', [])}"
            )

    # Output
    output = "\n".join(lines)
    if use_logging:
        logging.info(output)
    else:
        print(output)


def run_scheduled_scans(config_path='queen_config.json', run_once=False):
    """Run scheduled scans defined in config. If run_once=True perform a single scheduled event then return.
    """
    try:
        cfg = load_config(config_path)
    except Exception:
        cfg = {}
    sched = cfg.get('scheduled', {})
    if not sched.get('enabled') and not run_once:
        print('Scheduled scans not enabled in config')
        return

    interval = int(sched.get('interval_seconds', DEFAULT_SCHEDULE_INTERVAL))
    rounds = int(sched.get('rounds', DEFAULT_SCHEDULE_ROUNDS))
    concurrency = int(sched.get('concurrency', DEFAULT_SCHEDULE_CONCURRENCY))
    subnets = sched.get('subnets') or [cfg.get('target_ip_range', '10.0.0.0/24')]
    ports = sched.get('scan_ports') or cfg.get('scan_ports') or DEFAULT_SCAN_PORTS
    timeout = float(sched.get('timeout', DEFAULT_SCAN_TIMEOUT))

    print(f"Starting scheduled scans: every {interval}s, rounds={rounds}, concurrency={concurrency}, subnets={subnets}, ports={ports}, timeout={timeout}")

    try:
        set_live_allowed(cfg.get('allow_live_actions', False))
    except Exception:
        logger.exception('Failed to set live gate')

    q = Queen(config_path=config_path)

    def perform_rounds():
        findings = {}
        for r in range(rounds):
            for subnet in subnets:
                scouts = []
                for _ in range(concurrency):
                    s = q.hatch_broodling(role='scout', traits=['real_scan'])
                    s.telemetry['real_scan'] = True
                    scouts.append(s)
                for s in scouts:
                    try:
                        f, t = s.tick(ip_range=subnet, real_scan=True)
                        found = t.get('found_ips') or []
                        for ip in found:
                            findings.setdefault(ip, set())
                        for ip, ports_found in (t.get('ip_open_ports') or {}).items():
                            findings.setdefault(ip, set()).update(ports_found)
                    except Exception:
                        logger.exception('Scout scan failed')
        # write findings to schedule log
        try:
            os.makedirs(SCHEDULE_LOG_DIR, exist_ok=True)
            entry = {
                'time': datetime.utcnow().isoformat(),
                'subnets': subnets,
                'ports': ports,
                'findings': {ip: sorted(list(ps)) for ip, ps in findings.items()}
            }
            with open(SCHEDULE_LOG_FILE, 'a', encoding='utf-8') as lf:
                lf.write(json.dumps(entry) + '\n')
            logger.info('Scheduled scan logged to %s', SCHEDULE_LOG_FILE)
        except Exception:
            logger.exception('Failed to write scheduled scan log')

        # print summary
        print('\nScheduled scan summary:')
        for ip, ports in findings.items():
            print(' -', ip, 'ports:', sorted(list(ports)))
        return findings

    try:
        if run_once:
            res = perform_rounds()
            set_live_allowed(False)
            return res

        while True:
            perform_rounds()
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        print('\nScheduled scanning stopped by user')
    finally:
        set_live_allowed(False)


def main():
    # Load config
    cfg = load_config("queen_config.json")
    use_logging = cfg.get("use_logging", False)
    cycle_seconds = cfg.get("cycle_seconds", 30)

    if use_logging:
        setup_logging()

    # Start with one Queen
    queen = Queen(config_path="queen_config.json")
    colonies = [queen]

    while True:
        for q in list(colonies):
            # Run one cycle
            q.run_cycle()

            # Auto-spawn logic: if diversity drops below threshold
            if q.hive_stats.get("diversity_index", 0) < 2 and q.global_cycle > 3:
                new_queen = q.expand_colony(ip_range=f"192.168.1.{len(colonies)*16}/28")
                colonies.append(new_queen)

        # Collect summaries from all colonies
        for i, q in enumerate(colonies):
            summary = q.tick_all()  # or q.get_summary() depending on your Queen API
            header = f"\n=== Colony {i+1} ==="
            logging.info(header) if use_logging else print(header)

            render_dashboard(summary, verbose=False, use_logging=use_logging)

            # Show current policy quotas
            quotas = q.policy.current_quotas
            quota_line = f"   ⚖️ Quotas → CPU {quotas['cpu_pct']}, MEM {quotas['mem_mb']} MB"
            logging.info(quota_line) if use_logging else print(quota_line)
            divider = "=" * 40
            logging.info(divider) if use_logging else print(divider)

        time.sleep(max(1, cycle_seconds))



# --- End: Modules/Dashboard.py ---

# --- CLI menu for local device control ---
def _load_local_config(path="queen_config.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        return {}


def _save_local_config(cfg, path="queen_config.json"):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception as e:
        print("Failed to save config:", e)
        return False


def run_self_diagnostics_and_create_candidate(script_path=None):
    """Run lightweight self-diagnostics on the running Queen source and create a candidate patch file.
    Returns (candidate_path, report_path).
    The candidate is a full-file copy prefixed with a diagnostics header so operators can review/apply it via the menu.
    """
    import os, shutil, traceback, time
    from datetime import datetime
    script = os.path.abspath(script_path or __file__)
    try:
        with open(script, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return None, None
    report_lines = []
    # Syntax check
    try:
        compile(content, script, 'exec')
        report_lines.append('Syntax: OK')
    except Exception as e:
        report_lines.append('SyntaxError: ' + str(e))
        report_lines.append(traceback.format_exc())
    # Find TODO/FIXME markers
    todos = []
    for i, line in enumerate(content.splitlines()):
        if 'TODO' in line or 'FIXME' in line:
            todos.append((i+1, line.strip()))
    if todos:
        report_lines.append(f'Found {len(todos)} TODO/FIXME:')
        for ln, text in todos:
            report_lines.append(f'  Line {ln}: {text}')
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    outdir = os.path.join('.', 'proposed_patches')
    os.makedirs(outdir, exist_ok=True)
    candidate = os.path.join(outdir, f'Queen_candidate_{timestamp}.py')
    reportf = os.path.join(outdir, f'report_{timestamp}.txt')
    header = '# Proposed candidate generated by self-diagnostics (do NOT auto-apply)\n'
    header += '# Report:\n'
    for ln in report_lines:
        header += f'# {ln}\n'
    header += '\n'
    with open(candidate, 'w', encoding='utf-8') as cf:
        cf.write(header + content)
    with open(reportf, 'w', encoding='utf-8') as rf:
        rf.write('\n'.join(report_lines) + '\n')
    return candidate, reportf


def list_proposed_patches():
    d = os.path.join('.', 'proposed_patches')
    if not os.path.isdir(d):
        return []
    files = sorted([f for f in os.listdir(d) if f.startswith('Queen_candidate_') or f.endswith('.py')])
    return [os.path.join(d, f) for f in files]


def apply_candidate_patch(candidate_path, allow=False):
    """Apply the selected candidate by backing up the current Queen.py and copying the candidate into place.
    This operation is DISALLOWED unless allow=True (explicit operator approval).
    Returns (ok,msg).
    """
    import os, shutil
    from datetime import datetime
    if not allow:
        return False, 'Self-modification disallowed: missing explicit allow flag'
    script = os.path.abspath(__file__)
    if not os.path.exists(candidate_path):
        return False, 'candidate not found'
    bakdir = os.path.join('.', 'backups')
    os.makedirs(bakdir, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    backup = os.path.join(bakdir, f'Queen_backup_{ts}.py')
    try:
        shutil.copy2(script, backup)
        shutil.copy2(candidate_path, script)
        # Audit the replacement
        try:
            a = Audit(root='.')
            a.log('replacement', {'candidate': candidate_path, 'backup': backup, 'time': datetime.utcnow().isoformat()})
        except Exception:
            pass
        return True, f'Applied {candidate_path} -> {script} (backup at {backup})'
    except Exception as e:
        return False, str(e)


def cli_menu(path="queen_config.json"):
    """Simple text menu to enable/disable Queen capabilities for this device only."""
    cfg = _load_local_config(path)
    # defaults
    cfg.setdefault("allow_live_actions", False)
    cfg.setdefault("enable_real_scan", False)
    cfg.setdefault("max_hatch_per_cycle", 2)
    cfg.setdefault("enable_ssh_connector", False)
    cfg.setdefault("enable_adb_connector", False)
    cfg.setdefault("enable_scp_connector", False)
    cfg.setdefault("enable_tcp_connector", False)
    cfg.setdefault("scheduled", {
        "enabled": False,
        "interval_seconds": 300,
        "rounds": 3,
        "concurrency": 8,
        "subnets": [cfg.get('target_ip_range', '10.0.0.0/24')]
    })
    # feature toggles
    cfg.setdefault('use_masscan', False)
    cfg.setdefault('use_nmap', False)
    cfg.setdefault('use_ssdp', True)
    cfg.setdefault('use_mdns', True)
    cfg.setdefault('use_snmp', False)
    cfg.setdefault('use_app_enum', True)
    cfg.setdefault('use_multi_hop', False)
    cfg.setdefault('scan_ports', [80,443,53,22])
    cfg.setdefault('scan_timeout', 0.5)

    def show():
        print("\nQueen local configuration menu")
        print("1) Toggle live actions (currently: {} )".format(cfg["allow_live_actions"]))
        print("2) Toggle real_scan probing (currently: {} )".format(cfg["enable_real_scan"]))
        print("3) Set max_hatch_per_cycle (currently: {} )".format(cfg["max_hatch_per_cycle"]))
        print("4) Toggle SSH connector (currently: {} )".format(cfg["enable_ssh_connector"]))
        print("5) Toggle ADB connector (currently: {} )".format(cfg["enable_adb_connector"]))
        print("6) Toggle SCP connector (currently: {} )".format(cfg["enable_scp_connector"]))
        print("7) Toggle TCP connector (currently: {} )".format(cfg["enable_tcp_connector"]))
        print("8) Edit/add top-level config key")
        print("9) Save and exit")
        print("10) Exit without saving")
        print("11) Create systemd unit file (queen.service) in current directory")
        print("12) Attempt to install & start systemd service (requires root)")
        print("13) Configure scheduled scans (enabled/interval/rounds/concurrency/subnets)")
        print("14) Toggle Masscan usage (currently: {} )".format(cfg.get('use_masscan')))
        print("15) Toggle Nmap usage (currently: {} )".format(cfg.get('use_nmap')))
        print("16) Toggle SSDP probes (currently: {} )".format(cfg.get('use_ssdp')))
        print("17) Toggle mDNS probes (currently: {} )".format(cfg.get('use_mdns')))
        print("18) Toggle SNMP enumeration (currently: {} )".format(cfg.get('use_snmp')))
        print("19) Toggle App enumeration (HTTP/TLS) (currently: {} )".format(cfg.get('use_app_enum')))
        print("20) Toggle multi-hop/relay scanning (currently: {} )".format(cfg.get('use_multi_hop')))
        print("21) Set scan ports (current: {} )".format(cfg.get('scan_ports')))
        print("22) Set scan timeout (current: {}s )".format(cfg.get('scan_timeout')))
        print("23) Run one-shot scheduled scan now")
        print("34) Run one-shot scheduled scan now (background)")
        print("24) Delivery scoring and checks against last findings (non-interactive)")
        print("25) View scheduled scans log tail")
        print("26) Show genetic memory")
        print("27) Clear dedupe seen IPs")
        print("28) Interactive delivery check (select candidate + enter credentials)")
        print("29) Edit scoring weights (JSON input)")
        print("30) Configure SSH connector (host/port/user/key/password/enable)")
        print("31) Configure ADB connector (device/enable)")
        print("32) Configure SCP connector (host/port/user/key/password/enable)")
        print("33) Configure TCP connector (host/port/enable)")
        print("35) Add SSH private key to encrypted credential store")
        print("36) Retrieve SSH private key (one-time) from encrypted store")
        print("37) Kill-switch: disable live actions now (and save config)")
        print("38) Run self-diagnostics and propose a candidate patch (written to ./proposed_patches)")
        print("39) List proposed patches and apply selected candidate (requires confirmation)")

    while True:
        show()
        try:
            choice = input("Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting menu.")
            return
        if choice == "1":
            cfg["allow_live_actions"] = not cfg["allow_live_actions"]
            print("allow_live_actions =>", cfg["allow_live_actions"])
            try:
                set_live_allowed(cfg["allow_live_actions"])
            except Exception as e:
                logger.exception("Failed to propagate live flag: %s", e)
        elif choice == "2":
            cfg["enable_real_scan"] = not cfg["enable_real_scan"]
            print("enable_real_scan =>", cfg["enable_real_scan"])
        elif choice == "3":
            val = input("Enter max_hatch_per_cycle (int): ").strip()
            try:
                cfg["max_hatch_per_cycle"] = int(val)
            except Exception as e:
                logger.exception("Invalid integer for max_hatch_per_cycle: %s", e)
                print("Invalid integer")
        elif choice == "4":
            cfg["enable_ssh_connector"] = not cfg["enable_ssh_connector"]
            print("enable_ssh_connector =>", cfg["enable_ssh_connector"])
        elif choice == "5":
            cfg["enable_adb_connector"] = not cfg["enable_adb_connector"]
            print("enable_adb_connector =>", cfg["enable_adb_connector"])
        elif choice == "6":
            cfg["enable_scp_connector"] = not cfg["enable_scp_connector"]
            print("enable_scp_connector =>", cfg["enable_scp_connector"])
        elif choice == "7":
            cfg["enable_tcp_connector"] = not cfg["enable_tcp_connector"]
            print("enable_tcp_connector =>", cfg["enable_tcp_connector"])
        elif choice == "8":
            # Edit or add arbitrary config key
            k = input("Config key to edit (top-level only): ").strip()
            if not k:
                print("No key entered")
            else:
                cur = cfg.get(k, None)
                print(f"Current value for '{k}': {cur}")
                v = input("Enter new value (empty to toggle booleans, or JSON for complex types): ").strip()
                if v == "":
                    if isinstance(cur, bool):
                        cfg[k] = not cur
                        print(f"{k} => {cfg[k]}")
                    else:
                        print("No change (not a boolean). To set a value, provide one.")
                else:
                    try:
                        newv = json.loads(v)
                    except Exception:
                        newv = v
                    cfg[k] = newv
                    print(f"{k} => {cfg[k]}")
        elif choice == "9":
            ok = _save_local_config(cfg, path)
            if ok:
                # propagate live flag immediately
                try:
                    set_live_allowed(cfg.get("allow_live_actions", False))
                except Exception as e:
                    logger.exception("Failed to propagate live flag: %s", e)
                print("Configuration saved to", path)
            return
        elif choice == "10":
            print("Discarding changes and exiting.")
            return
        elif choice == "11":
            # create a systemd unit file in current directory
            try:
                import sys
                script = os.path.abspath(__file__)
                python_exec = sys.executable or "/usr/bin/env python3"
                workdir = os.path.dirname(script)
                svc = f"""[Unit]\nDescription=Queen daemon (local)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={python_exec} {script} --config {os.path.abspath(path)}\nWorkingDirectory={workdir}\nRestart=on-failure\nRestartSec=10\nEnvironment=ALLOW_LIVE=1\n\n[Install]\nWantedBy=multi-user.target\n"""
                target = os.path.join(os.getcwd(), 'queen.service')
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(svc)
                print('Wrote systemd unit to', target)
                print('To install as a system service run as root:\n  sudo mv queen.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable queen.service && sudo systemctl start queen.service')
            except Exception as e:
                print('Failed to create unit file:', e)
        elif choice == "12":
            # attempt to install and start the service (requires root)
            try:
                if os.geteuid() != 0:
                    print('Installation requires root. Re-run menu as root or use option 8 to create a unit file for manual install.')
                else:
                    import sys
                    script = os.path.abspath(__file__)
                    python_exec = sys.executable or "/usr/bin/env python3"
                    workdir = os.path.dirname(script)
                    svc = f"""[Unit]\nDescription=Queen daemon (local)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={python_exec} {script} --config {os.path.abspath(path)}\nWorkingDirectory={workdir}\nRestart=on-failure\nRestartSec=10\nEnvironment=ALLOW_LIVE=1\n\n[Install]\nWantedBy=multi-user.target\n"""
                    dest = '/etc/systemd/system/queen.service'
                    with open(dest, 'w', encoding='utf-8') as f:
                        f.write(svc)
                    print('Wrote unit to', dest)
                    try:
                        subprocess.run(['systemctl', 'daemon-reload'], check=False)
                        subprocess.run(['systemctl', 'enable', 'queen.service'], check=False)
                        subprocess.run(['systemctl', 'start', 'queen.service'], check=False)
                        print('Attempted to enable and start queen.service (check systemctl status for details)')
                    except Exception as e:
                        print('Failed to start service via systemctl:', e)
            except Exception as e:
                print('Error during installation:', e)
        elif choice == "13":
            sched = cfg.setdefault('scheduled', {})
            print('Current schedule:', sched)
            en = input('Enable scheduled scans? (y/n): ').strip().lower()
            if en in ('y','yes'):
                sched['enabled'] = True
            elif en in ('n','no'):
                sched['enabled'] = False
            try:
                iv = input(f"Interval seconds (current {sched.get('interval_seconds',300)}): ").strip()
                if iv:
                    sched['interval_seconds'] = int(iv)
            except Exception as e:
                logger.exception('Invalid interval value: %s', e)
            try:
                rd = input(f"Rounds per scheduled event (current {sched.get('rounds',3)}): ").strip()
                if rd:
                    sched['rounds'] = int(rd)
            except Exception as e:
                logger.exception('Invalid rounds value: %s', e)
            try:
                conc = input(f"Concurrency (scouts per subnet) (current {sched.get('concurrency',8)}): ").strip()
                if conc:
                    sched['concurrency'] = int(conc)
            except Exception as e:
                logger.exception('Invalid concurrency value: %s', e)
            subs = input(f"Subnets (comma-separated) (current {','.join(sched.get('subnets',[]))}): ").strip()
            if subs:
                sched['subnets'] = [s.strip() for s in subs.split(',') if s.strip()]
            cfg['scheduled'] = sched
            print('Updated schedule:', sched)
        elif choice == '14':
            cfg['use_masscan'] = not cfg.get('use_masscan', False)
            print('use_masscan =>', cfg['use_masscan'])
        elif choice == '15':
            cfg['use_nmap'] = not cfg.get('use_nmap', False)
            print('use_nmap =>', cfg['use_nmap'])
        elif choice == '16':
            cfg['use_ssdp'] = not cfg.get('use_ssdp', True)
            print('use_ssdp =>', cfg['use_ssdp'])
        elif choice == '17':
            cfg['use_mdns'] = not cfg.get('use_mdns', True)
            print('use_mdns =>', cfg['use_mdns'])
        elif choice == '18':
            cfg['use_snmp'] = not cfg.get('use_snmp', False)
            print('use_snmp =>', cfg['use_snmp'])
        elif choice == '19':
            cfg['use_app_enum'] = not cfg.get('use_app_enum', True)
            print('use_app_enum =>', cfg['use_app_enum'])
        elif choice == '20':
            cfg['use_multi_hop'] = not cfg.get('use_multi_hop', False)
            print('use_multi_hop =>', cfg['use_multi_hop'])
        elif choice == '21':
            val = input('Enter comma-separated ports (e.g. 22,80,443): ').strip()
            try:
                cfg['scan_ports'] = [int(p.strip()) for p in val.split(',') if p.strip()]
                print('scan_ports =>', cfg['scan_ports'])
            except Exception as e:
                logger.exception('Invalid port list: %s', e)
                print('Invalid ports')
        elif choice == '22':
            val = input('Enter scan timeout seconds (float): ').strip()
            try:
                cfg['scan_timeout'] = float(val)
                print('scan_timeout =>', cfg['scan_timeout'])
            except Exception as e:
                logger.exception('Invalid timeout: %s', e)
                print('Invalid timeout')
        elif choice == '23':
            print('Running one-shot scheduled scan now...')
            try:
                from Queen import run_scheduled_scans as _r
                _r(config_path=path, run_once=True)
            except Exception as e:
                logger.exception('Failed to run scheduled scan: %s', e)
        elif choice == '34':
            print('Starting one-shot scheduled scan in background...')
            try:
                def bg_scan():
                    try:
                        run_scheduled_scans(config_path=path, run_once=True)
                    except Exception as e:
                        logger.exception('Background scheduled scan failed: %s', e)
                t = threading.Thread(target=bg_scan, daemon=True)
                t.start()
            except Exception as e:
                logger.exception('Failed to start background scan: %s', e)
                print('Failed to start scheduled scan')
        elif choice == '24':
            # Delivery checks: pick last scan findings and run safe delivery checks
            try:
                logf = os.path.join('.', 'logs', 'scheduled_scans.jsonl')
                if not os.path.exists(logf):
                    print('No scheduled scan log found')
                else:
                    with open(logf, 'r') as lf:
                        lines = [l for l in lf if l.strip()]
                        if not lines:
                            print('No entries in scheduled scan log')
                        else:
                            last = json.loads(lines[-1])
                            findings = last.get('findings', {})
                            print('Running delivery scoring on', len(findings), 'hosts')
                            q = Queen(config_path=path)
                            candidates = q.score_candidates(findings)
                            print('Top candidates:')
                            for c in candidates[:10]:
                                print(' ', c)
            except Exception as e:
                logger.exception('Delivery check failed: %s', e)
            # Delivery checks: pick last scan findings and run safe delivery checks
            try:
                logf = os.path.join('.', 'logs', 'scheduled_scans.jsonl')
                if not os.path.exists(logf):
                    print('No scheduled scan log found')
                else:
                    with open(logf, 'r') as lf:
                        lines = [l for l in lf if l.strip()]
                        if not lines:
                            print('No entries in scheduled scan log')
                        else:
                            last = json.loads(lines[-1])
                            findings = last.get('findings', {})
                            print('Running delivery scoring on', len(findings), 'hosts')
                            q = Queen(config_path=path)
                            candidates = q.score_candidates(findings)
                            print('Top candidates:')
                            for c in candidates[:10]:
                                print(' ', c)
            except Exception as e:
                logger.exception('Delivery check failed: %s', e)
        elif choice == '25':
            # view scheduled log tail
            try:
                logf = os.path.join('.', 'logs', 'scheduled_scans.jsonl')
                if not os.path.exists(logf):
                    print('No scheduled scan log found')
                else:
                    n = input('Lines to show from end (default 10): ').strip() or '10'
                    try:
                        n = int(n)
                    except Exception:
                        n = 10
                    with open(logf, 'r') as lf:
                        lines = [l for l in lf if l.strip()]
                        for line in lines[-n:]:
                            print(line.strip())
            except Exception as e:
                logger.exception('Failed to read scheduled log: %s', e)
        elif choice == '26':
            try:
                q = Queen(config_path=path)
                print('Genetic memory:', getattr(q, 'genetic_memory', []))
            except Exception as e:
                logger.exception('Failed to load queen for genetic memory: %s', e)
        elif choice == '27':
            try:
                qm = QueenMemory()
                qm._seen_ips = {}
                qm._save_seen_ips()
                print('Cleared dedupe seen IPs')
            except Exception as e:
                logger.exception('Failed to clear dedupe: %s', e)
        elif choice == '28':
            # Interactive delivery check against selected candidate
            try:
                logf = os.path.join('.', 'logs', 'scheduled_scans.jsonl')
                if not os.path.exists(logf):
                    print('No scheduled scan log found')
                else:
                    with open(logf, 'r') as lf:
                        lines = [l for l in lf if l.strip()]
                    if not lines:
                        print('No scheduled scan entries')
                    else:
                        last = json.loads(lines[-1])
                        findings = last.get('findings', {})
                        q = Queen(config_path=path)
                        candidates = q.score_candidates(findings)
                        if not candidates:
                            print('No candidates found')
                        else:
                            for i, c in enumerate(candidates[:20]):
                                print(f"{i}) score={c[0]} ip={c[1]} ports={c[2]['ports']}")
                            sel = input('Select candidate number: ').strip()
                            try:
                                sel = int(sel)
                            except Exception:
                                print('Invalid selection')
                                sel = None
                            if sel is not None and 0 <= sel < len(candidates):
                                ip = candidates[sel][1]
                                username = input('Username (leave blank to skip auth): ').strip() or None
                                password = None
                                key = None
                                if username:
                                    pw = input('Password (leave blank to use key): ')
                                    if pw:
                                        password = pw
                                    else:
                                        kp = input('Path to private key (leave blank to skip): ').strip() or None
                                        key = kp
                                persist = input('Persist credentials encrypted? (y/n): ').strip().lower()
                                if persist in ('y', 'yes') and (username and (password or key)):
                                    pp = input('Passphrase to encrypt with: ')
                                    cred = {'username': username, 'password': password, 'key': key}
                                    enc = encrypt_blob(json.dumps(cred), pp)
                                    os.makedirs('modules', exist_ok=True)
                                    with open(os.path.join('modules', 'credentials.json.enc'), 'w') as ef:
                                        ef.write(enc)
                                    print('Credentials persisted to modules/credentials.json.enc')
                                print('Running delivery check (non-destructive) ...')
                                res = q.safe_delivery_check(ip, port=22, username=username, key=key, password=password)
                                print('Result:', res)
                                deploy_choice = input('Install agent on this host and optionally create reverse tunnel? (y/n): ').strip().lower()
                                if deploy_choice in ('y','yes'):
                                    agent_path = os.path.join(os.path.dirname(__file__), 'modules', 'agent.sh')
                                    tunnel_conf = None
                                    key_content = None
                                    tt = input('Create reverse tunnel from the target back to relay? (y/n): ').strip().lower()
                                    if tt in ('y','yes'):
                                        relay_host = input('Relay host (IP/FQDN): ').strip()
                                        relay_port = input('Relay SSH port (default 22): ').strip() or '22'
                                        relay_user = input('Relay username: ').strip()
                                        remote_port = input('Remote port on relay for reverse mapping (e.g. 2222): ').strip() or '2222'
                                        tunnel_conf = {'relay_host': relay_host, 'relay_port': int(relay_port), 'relay_user': relay_user, 'remote_port': int(remote_port)}
                                        keyp = input('Path to private key file to use for tunnel (local path to this control host): ').strip()
                                        try:
                                            with open(keyp,'r') as kf:
                                                key_content = kf.read()
                                        except Exception as e:
                                            print('Failed to read key file:', e)
                                            key_content = None
                                    # confirm operator consent
                                    conf = input('Confirm you have authorization to install agent on this host (type YES to confirm): ').strip()
                                    if conf == 'YES':
                                        try:
                                            if deployer_mod:
                                                dres = deployer_mod.deploy_agent(ip, username=username, password=password, key_path=key, agent_local_path=agent_path, sudo=True, timeout=10, key_content=key_content, tunnel=tunnel_conf)
                                                print('Deploy result:', dres)
                                            else:
                                                print('Deployer module not available')
                                        except Exception as e:
                                            logger.exception('Deploy attempt failed: %s', e)
                                            print('Deploy failed:', e)
                                    else:
                                        print('Deployment aborted: operator did not confirm')
            except Exception as e:
                logger.exception('Interactive delivery check failed: %s', e)
        elif choice == '29':
            try:
                cur = cfg.get('scoring_weights', {})
                print('Current scoring weights:', cur)
                raw = input('Enter JSON object for scoring weights (or blank to cancel): ').strip()
                if raw:
                    try:
                        nw = json.loads(raw)
                        cfg['scoring_weights'] = nw
                        print('Updated scoring_weights')
                    except Exception as e:
                        logger.exception('Invalid JSON for scoring weights: %s', e)
                        print('Invalid JSON')
            except Exception as e:
                logger.exception('Failed to edit scoring weights: %s', e)
        elif choice == '30':
            try:
                conn = cfg.setdefault('connectors', {}).get('ssh', {})
                conn = cfg['connectors'].setdefault('ssh', conn or {})
                print('Current SSH config:', conn)
                en = input('Enable SSH? (y/n): ').strip().lower()
                conn['enabled'] = True if en in ('y','yes') else False
                h = input(f"Host (current: {conn.get('host')}): ").strip()
                if h:
                    conn['host'] = h
                p = input(f"Port (current: {conn.get('port',22)}): ").strip()
                if p:
                    try:
                        conn['port'] = int(p)
                    except Exception:
                        print('Invalid port value, keeping existing')
                u = input(f"User (current: {conn.get('user')}): ").strip()
                if u:
                    conn['user'] = u
                k = input('Path to private key (leave blank to skip): ').strip()
                if k:
                    conn['key'] = k
                pw = input('Password (leave blank to keep/none): ').strip()
                if pw:
                    conn['password'] = pw
                cfg['connectors']['ssh'] = conn
                print('Updated SSH config')
            except Exception as e:
                logger.exception('Failed to edit SSH connector: %s', e)
                print('Failed to edit SSH connector')
        elif choice == '31':
            try:
                conn = cfg.setdefault('connectors', {}).get('adb', {})
                conn = cfg['connectors'].setdefault('adb', conn or {})
                print('Current ADB config:', conn)
                en = input('Enable ADB? (y/n): ').strip().lower()
                conn['enabled'] = True if en in ('y','yes') else False
                d = input(f"Device serial (current: {conn.get('device')}): ").strip()
                if d:
                    conn['device'] = d
                cfg['connectors']['adb'] = conn
                print('Updated ADB config')
            except Exception as e:
                logger.exception('Failed to edit ADB connector: %s', e)
                print('Failed to edit ADB connector')
        elif choice == '32':
            try:
                conn = cfg.setdefault('connectors', {}).get('scp', {})
                conn = cfg['connectors'].setdefault('scp', conn or {})
                print('Current SCP config:', conn)
                en = input('Enable SCP? (y/n): ').strip().lower()
                conn['enabled'] = True if en in ('y','yes') else False
                h = input(f"Host (current: {conn.get('host')}): ").strip()
                if h:
                    conn['host'] = h
                p = input(f"Port (current: {conn.get('port',22)}): ").strip()
                if p:
                    try:
                        conn['port'] = int(p)
                    except Exception:
                        print('Invalid port value, keeping existing')
                u = input(f"User (current: {conn.get('user')}): ").strip()
                if u:
                    conn['user'] = u
                k = input('Path to private key (leave blank to skip): ').strip()
                if k:
                    conn['key'] = k
                pw = input('Password (leave blank to keep/none): ').strip()
                if pw:
                    conn['password'] = pw
                cfg['connectors']['scp'] = conn
                print('Updated SCP config')
            except Exception as e:
                logger.exception('Failed to edit SCP connector: %s', e)
                print('Failed to edit SCP connector')
        elif choice == '33':
            try:
                conn = cfg.setdefault('connectors', {}).get('tcp', {})
                conn = cfg['connectors'].setdefault('tcp', conn or {})
                print('Current TCP config:', conn)
                en = input('Enable TCP? (y/n): ').strip().lower()
                conn['enabled'] = True if en in ('y','yes') else False
                h = input(f"Host (current: {conn.get('host')}): ").strip()
                if h:
                    conn['host'] = h
                p = input(f"Port (current: {conn.get('port')}): ").strip()
                if p:
                    try:
                        conn['port'] = int(p)
                    except Exception:
                        print('Invalid port value, keeping existing')
                cfg['connectors']['tcp'] = conn
                print('Updated TCP config')
            except Exception as e:
                logger.exception('Failed to edit TCP connector: %s', e)
                print('Failed to edit TCP connector')
        elif choice == '35':
            try:
                default_path = os.path.expanduser('~/.ssh/id_ed25519')
                p = input(f"Path to private key (default: {default_path}): ").strip() or default_path
                if not os.path.exists(p):
                    print('File not found:', p)
                else:
                    label = input('Label to store key under (default: ssh_default): ').strip() or 'ssh_default'
                    import getpass
                    pw = getpass.getpass('Enter passphrase to encrypt the key: ')
                    pw2 = getpass.getpass('Confirm passphrase: ')
                    if pw != pw2:
                        print('Passphrases do not match')
                    else:
                        with open(p, 'rb') as fh:
                            data = fh.read()
                        cs = CredentialStore()
                        ok, msg = cs.save_key(label, data, pw)
                        if ok:
                            print('Key stored encrypted under label:', label)
                        else:
                            print('Failed to store key:', msg)
            except Exception as e:
                logger.exception('Failed to add key to credential store: %s', e)
                print('Failed to store key')
        elif choice == '36':
            try:
                label = input('Label to retrieve (default: ssh_default): ').strip() or 'ssh_default'
                import getpass, tempfile, stat
                pw = getpass.getpass('Enter passphrase to decrypt the key: ')
                cs = CredentialStore()
                ok, msg, raw = cs.retrieve_key_one_time(label, pw)
                if not ok:
                    print('Failed to retrieve key:', msg)
                else:
                    # write to secure temp file
                    tf = tempfile.NamedTemporaryFile(prefix='queen_key_', delete=False)
                    tf.write(raw)
                    tf.flush()
                    tf.close()
                    try:
                        os.chmod(tf.name, 0o600)
                    except Exception:
                        pass
                    print('Key written to:', tf.name)
                    print('This key was removed from the encrypted store (one-time). Remove the temp file after use.')
                    # offer to auto-set SSH connector to use this key now
                    try:
                        ans = input('Set SSH connector to use this key now and enable it? (y/n): ').strip().lower()
                        if ans in ('y', 'yes'):
                            conn = cfg.setdefault('connectors', {}).setdefault('ssh', {})
                            conn['key'] = tf.name
                            conn['enabled'] = True
                            # preserve existing host/port/user if present
                            cfg['connectors']['ssh'] = conn
                            saved = _save_local_config(cfg, path)
                            if saved:
                                print('SSH connector updated in config and enabled.')
                            else:
                                print('Failed to save updated config; you may set connector manually via option 30.')
                    except Exception:
                        pass
            except Exception as e:
                logger.exception('Failed to retrieve key: %s', e)
                print('Failed to retrieve key')
        elif choice == '37':
            # Kill-switch: disable live actions and persist to config
            try:
                cfg['allow_live_actions'] = False
                ok = _save_local_config(cfg, path)
                try:
                    set_live_allowed(False)
                except Exception:
                    pass
                print('Kill-switch activated: live actions disabled and saved to config')
                print('Note: to fully stop background threads, exit this menu and terminate the process if needed.')
            except Exception as e:
                logger.exception('Failed to activate kill-switch: %s', e)
                print('Failed to activate kill-switch:', e)
        elif choice == '38':
            # Run self-diagnostics and propose a candidate patch
            try:
                cand, rpt = run_self_diagnostics_and_create_candidate()
                if cand and rpt:
                    print('Candidate patch created:', cand)
                    print('Diagnostic report:', rpt)
                else:
                    print('Diagnostics failed to produce a candidate')
            except Exception as e:
                logger.exception('Diagnostics failed: %s', e)
                print('Diagnostics failed:', e)
        elif choice == '39':
            # List proposed candidates and offer to apply one (STRICT: requires exact filename and APPLY token)
            try:
                cands = list_proposed_patches()
                if not cands:
                    print('No proposed candidates found in ./proposed_patches')
                else:
                    for i, c in enumerate(cands):
                        print(f"{i}) {c}")
                    sel = input('Select candidate number to apply (or blank to cancel): ').strip()
                    if sel == '':
                        print('Cancelled')
                    else:
                        try:
                            si = int(sel)
                            if 0 <= si < len(cands):
                                # Strong confirmation: require exact filename match
                                basename = os.path.basename(cands[si])
                                expect = input(f"Type the exact filename '{basename}' to confirm apply, or blank to cancel: ").strip()
                                if expect != basename:
                                    print('Filename mismatch or cancelled; aborting')
                                else:
                                    tok = input("Type APPLY to proceed with applying the candidate (this is irreversible): ").strip()
                                    if tok != 'APPLY':
                                        print('Did not receive APPLY token; aborting')
                                    else:
                                        # final human confirmation
                                        final = input('FINAL CONFIRM: type CONFIRM-APPLY to proceed: ').strip()
                                        if final != 'CONFIRM-APPLY':
                                            print('Final confirmation not received; aborting')
                                        else:
                                            ok, msg = apply_candidate_patch(cands[si], allow=True)
                                            if ok:
                                                print('Patch applied:', msg)
                                                print('Note: the running process must be restarted for changes to take effect.')
                                            else:
                                                print('Failed to apply patch:', msg)
                            else:
                                print('Invalid selection')
                        except Exception as e:
                            print('Invalid selection:', e)
            except Exception as e:
                logger.exception('Failed to apply candidate: %s', e)
                print('Failed to apply candidate:', e)
        else:
            print("Unknown option")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(prog='Queen', description='Queen CLI')
    parser.add_argument('--menu', action='store_true', help='Open local capabilities menu')
    parser.add_argument('--config', default='queen_config.json', help='Path to local config file')
    parser.add_argument('--dashboard', action='store_true', help='Show a concise Queen dashboard and exit')
    parser.add_argument('--watch', action='store_true', help='Continuously refresh the dashboard (use with --dashboard)')
    parser.add_argument('--interval', type=float, default=2.0, help='Refresh interval seconds when --watch is used')
    parser.add_argument('--schedule', action='store_true', help='Run scheduled scans per config (blocking)')
    args = parser.parse_args()

    if args.menu:
        cli_menu(path=args.config)
    elif args.schedule:
        run_scheduled_scans(config_path=args.config)
    elif args.dashboard:
        q = None
        try:
            q = Queen(config_path=args.config)
        except Exception as e:
            logger.exception("Unhandled exception: %s", e)
            print('Failed to instantiate Queen for dashboard')
        if q:
            try:
                if args.watch:
                    interval = max(0.5, float(args.interval))
                    while True:
                        # clear screen
                        print('\033c', end='')
                        # attempt to refresh state from latest checkpoint if available
                        try:
                            if hasattr(q, 'storage') and q.storage:
                                try:
                                    snap = q.storage.restore()
                                except Exception:
                                    snap = None
                                if isinstance(snap, dict):
                                    q.global_cycle = snap.get('global_cycle', getattr(q, 'global_cycle', None))
                                    q.hive_stats = {
                                        'avg_fitness': snap.get('avg_fitness'),
                                        'diversity_index': snap.get('diversity_index'),
                                        'role_distribution': snap.get('role_distribution'),
                                        'lineage_avg_depth': snap.get('lineage_avg_depth'),
                                        'ips_discovered_total': snap.get('ips_discovered_total'),
                                        'open_ports_total': snap.get('open_ports_total'),
                                        'innovation_events': snap.get('innovation_events', []),
                                    }
                                    q.genetic_memory = snap.get('genetic_memory') or getattr(q, 'genetic_memory', [])
                                    # try to build simple colonies list from broodling traits if present
                                    try:
                                        brood = snap.get('broodling_traits', [])
                                        q.colonies = []
                                        # collect discovered ips/open ports from broodling telemetry
                                        ip_open_map = {}
                                        discovered = []
                                        for b in brood:
                                            t = b.get('telemetry') or {}
                                            for ip in (t.get('found_ips') or []):
                                                if ip not in discovered:
                                                    discovered.append(ip)
                                            ip_open = t.get('ip_open_ports') or {}
                                            for ip, ports in ip_open.items():
                                                ip_open_map.setdefault(ip, set()).update(ports or [])
                                        if discovered or ip_open_map:
                                            q.colonies.append({'ip_range': None, 'queen': q, 'discovered_ips': discovered, 'ip_open_ports': {ip: sorted(list(ps)) for ip, ps in ip_open_map.items()}})
                                    except Exception:
                                        pass
                                # also attempt to read live_state.json for most recent runtime snapshot
                                try:
                                    livef = os.path.join('.', 'logs', 'live_state.json')
                                    if os.path.exists(livef):
                                        with open(livef, 'r', encoding='utf-8') as lf:
                                            lively = json.load(lf)
                                        q.global_cycle = lively.get('global_cycle', q.global_cycle)
                                        # best-effort reflect broodling/colonies counts
                                        try:
                                            # don't overwrite detailed colonies if present
                                            if not getattr(q, 'colonies', []):
                                                q.colonies = []
                                            # set hive_stats keys present
                                            q.hive_stats.update(lively.get('hive_stats') or {})
                                        except Exception:
                                            pass
                                except Exception:
                                    pass

                        except Exception:
                            pass
                        q.print_dashboard(max_entries=200, show_more=True)
                        try:
                            time.sleep(interval)
                        except KeyboardInterrupt:
                            print('\nExiting dashboard watch.')
                            break
                else:
                    q.print_dashboard(max_entries=200, show_more=True)
            except KeyboardInterrupt:
                print('\nExiting dashboard.')
    else:
        # Default behavior: start automatic queen cycles
        cfg = load_config(args.config)
        cycle_seconds = cfg.get("cycle_seconds", 30)
        print("Starting Queen automatic loop. Live actions allowed:", end=' ')
        q = None
        try:
            q = Queen(config_path=args.config)
            print(bool(q.allow_live))
        except Exception as e:
            print("failed to instantiate Queen:", e)
            raise

        try:
            while True:
                try:
                    successor = q.run_cycle()
                except Exception as e:
                    print("Cycle error:", e)
                # concise status line
                print(f"[Queen] cycle={q.global_cycle} broodlings={len(q.broodlings)} colonies={len(q.colonies)} avg_fit={q.hive_stats.get('avg_fitness')}")
                time.sleep(max(0.1, cycle_seconds))
        except KeyboardInterrupt:
            print('\nKeyboard interrupt received. Graceful shutdown...')
            try:
                if q and q.storage:
                    q.storage.checkpoint(q)
            except Exception as e:
                logger.exception("Unhandled exception: %s", e)
                pass
            print('Shutdown complete.')
