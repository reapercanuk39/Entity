# QueenCore/Hive/Audit.py

import json
import os
import shutil
from datetime import datetime

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
        }

    def _archive_if_needed(self, path):
        """Archive log if it exceeds max_log_size."""
        if os.path.exists(path) and os.path.getsize(path) >= self.max_log_size:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_name = f"{path}.{timestamp}.archive"
            try:
                shutil.move(path, archive_name)
                print(f"[Audit] Archived {path} → {archive_name}")
            except Exception as e:
                print(f"[Audit] Failed to archive {path}: {e}")

    def _write(self, path, entry):
        try:
            self._archive_if_needed(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[Audit] Failed to write log entry to {path}: {e}")

    def _log(self, category, entry):
        entry["time"] = datetime.utcnow().isoformat()
        path = self.log_paths.get(category)
        if path:
            self._write(path, entry)
        else:
            print(f"[Audit] Unknown log category: {category}")

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


# 🔎 New: Auditor class for error logging
class Auditor:
    def __init__(self, log_dir="modules/logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "errors.jsonl")

    def log_error(self, source, message, severity="error"):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": source,
            "severity": severity,
            "message": message
        }
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            print(f"[Audit] Logged {severity} from {source}: {message}")
        except Exception as e:
            print(f"[Audit] Failed to log error: {e}")
