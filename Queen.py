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
from collections import Counter
from datetime import datetime
from typing import Dict, Any


# Telemetry shim
class Telemetry:
    def snapshot(self):
        return {"cpu_pct":0, "mem_mb":0, "traits": []}
    def environment(self):
        return {"avg_cpu_pct":0.0, "avg_mem_mb":0.0}



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
        except Exception:
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

    def log(self, category, entry):
        try:
            self._log(category, entry if isinstance(entry, dict) else {"message": entry})
        except Exception:
            pass

    def log_policy_change(self, message):
        try:
            self._log("policy", {"message": message})
        except Exception:
            pass

    def log_queen_state(self, queen):
        try:
            self._log("queen_state", {"global_cycle": getattr(queen, 'global_cycle', None), "hive_stats": getattr(queen, 'hive_stats', {})})
        except Exception:
            pass


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
                    except Exception:
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
                print(f"Checkpoint saved → {path}")
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
    except Exception:
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
            except Exception:
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
            except Exception:
                # fall through to TCP-based discovery
                hosts = []

        # Fallback: TCP-based lightweight discovery by attempting connections to common ports.
        # Parse the cidr to derive a /24 prefix (best-effort). This is intentionally conservative.
        try:
            base = str(cidr).split('/')[0]
            parts = base.split('.')
            prefix = '.'.join(parts[0:3])
        except Exception:
            return []

        ips = [f"{prefix}.{i}" for i in range(1, 255)]
        common_ports = [80, 443, 22]
        try:
            import concurrent.futures
            def probe(ip):
                try:
                    openp = self._tcp_scan_ports(ip, common_ports, timeout=0.12)
                    return ip if openp else None
                except Exception:
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=60) as exe:
                futures = {exe.submit(probe, ip): ip for ip in ips}
                for f in concurrent.futures.as_completed(futures, timeout=20):
                    try:
                        res = f.result()
                    except Exception:
                        res = None
                    if res:
                        hosts.append(res)
        except Exception:
            # Last-resort: try only the base gateway/start ip
            try:
                gw = f"{prefix}.1"
                if self._tcp_scan_ports(gw, common_ports, timeout=0.12):
                    hosts.append(gw)
            except Exception:
                pass

        return hosts

    def tick(self, ip_range=None, ports=None, real_scan=False, **kwargs):
        # Determine start ip and prefix
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
        except Exception:
            prefix = '10.0.0'

        scan_ports = ports or [22, 80, 443, 8080]
        found_ips = []
        ip_open_ports = {}

        # If real_scan requested (or trait set), attempt ARP discovery + TCP connect scans
        use_real = real_scan or self.telemetry.get('real_scan') or ('real_scan' in (self.traits or []))
        if use_real:
            # ARP discover neighbors on the /24
            cidr = f"{prefix}.0/24"
            try:
                hosts = self._arp_discover(cidr) if getattr(self, '_HAS_SCAPY', False) else []
            except Exception:
                hosts = []
            # include start_ip if not found
            if start_ip and start_ip not in hosts:
                hosts.append(start_ip)
            # perform concurrent TCP scans for each host
            try:
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as exe:
                    futures = {exe.submit(self._tcp_scan_ports, h, scan_ports, 0.5): h for h in hosts}
                    for f in concurrent.futures.as_completed(futures, timeout=10):
                        h = futures[f]
                        try:
                            openp = f.result()
                        except Exception:
                            openp = []
                        if openp:
                            found_ips.append(h)
                            ip_open_ports[h] = openp
            except Exception:
                # fallback: single-threaded scan of start_ip
                try:
                    openp = self._tcp_scan_ports(start_ip, scan_ports, timeout=0.5)
                    if openp:
                        found_ips.append(start_ip)
                        ip_open_ports[start_ip] = openp
                except Exception:
                    pass
        else:
            # Simulated discovery (non-invasive) retains previous behavior
            num_found = random.randint(0, 5)
            for _ in range(num_found):
                last = random.randint(2, 250)
                ip = f"{prefix}.{last}"
                found_ips.append(ip)
                open_ports = [p for p in scan_ports if random.random() < 0.35]
                ip_open_ports[ip] = open_ports

        # Populate telemetry
        self.telemetry["ip_ranges"] = [f"{prefix}.0/24"]
        self.telemetry["found_ips"] = found_ips
        self.telemetry["ip_open_ports"] = ip_open_ports
        self.telemetry["ips_discovered"] = len(found_ips)
        self.telemetry["open_ports"] = list({p for ports in ip_open_ports.values() for p in ports})
        self.telemetry["blocked_ports"] = []

        # Resource telemetry
        self.telemetry["cpu_pct"] = random.uniform(5, 60)
        self.telemetry["ram_pct"] = random.uniform(5, 60)
        self.telemetry["io_wait"] = random.uniform(0, 30)

        # Environment telemetry
        self.telemetry["latency_ms"] = random.randint(5, 200)
        self.telemetry["os_type"] = random.choice(["linux", "windows", "macos"])
        self.telemetry["connected_wifi"] = True

        # Apply trait flags and fusions
        self.apply_trait_flags(["network_probe", "port_scan"])
        self.apply_trait_fusion({("network_probe", "stealth_mode"): "ghost_probe"})

        # Fitness calculation
        self.fitness = len(self.telemetry["open_ports"]) * 3 + len(found_ips)
        self.cycle += 1

        # Audit logging
        if found_ips:
            audit.log_trait_activity(self, "multi_range_probe", f"FoundIPs={found_ips}")
            try:
                audit.log_ip_check(self, found_ips)
            except Exception:
                pass
        if self.telemetry["open_ports"]:
            audit.log_trait_activity(self, "port_scan", f"Open={self.telemetry['open_ports']}")
            try:
                audit.log_port_check(self, self.telemetry['open_ports'], self.telemetry.get('blocked_ports', []))
            except Exception:
                pass
        if self.fused_traits:
            audit.log_trait_fusion(self, self.fused_traits, ["network_probe", "stealth_mode"])

        return self.fitness, self.telemetry


class Scanner(BroodlingBase):
    def tick(self, ports=None, **kwargs):
        scanned_ports = ports or [22, 80, 443]
        open_ports = [p for p in scanned_ports if random.random() < 0.3]
        blocked_ports = [p for p in scanned_ports if p not in open_ports]

        self.telemetry["scanned_ports"] = scanned_ports
        self.telemetry["open_ports"] = open_ports
        self.telemetry["blocked_ports"] = blocked_ports

        self.apply_trait_flags(["low_signature_scan"])

        self.fitness = len(open_ports) * 2
        self.cycle += 1

        audit.log_trait_activity(self, "scanner", f"Scanned={scanned_ports}, Open={open_ports}")
        try:
            audit.log_port_check(self, open_ports, blocked_ports)
        except Exception:
            pass
        return self.fitness, self.telemetry


class Defender(BroodlingBase):
    def tick(self, **kwargs):
        blocked_ports = random.sample(range(20, 1024), random.randint(0, 5))
        self.telemetry["blocked_ports"] = blocked_ports
        self.telemetry["cpu_pct"] = random.uniform(5, 50)
        self.telemetry["ram_pct"] = random.uniform(5, 50)
        self.telemetry["io_wait"] = random.uniform(0, 20)

        self.fitness = len(blocked_ports)
        self.cycle += 1

        if "firewall_awareness" in self.traits:
            audit.log_trait_activity(self, "firewall_awareness", f"Blocked={blocked_ports}")

        try:
            audit.log_port_check(self, [], blocked_ports)
        except Exception:
            pass

        return self.fitness, self.telemetry


class Builder(BroodlingBase):
    def tick(self, **kwargs):
        resources_built = random.choice(["node", "link", "cache", "relay"])
        self.telemetry["resources_built"] = resources_built
        self.telemetry["expansion_trigger"] = random.choice([True, False])

        self.apply_trait_fusion({
            ("trait_fusion", "builder"): "builder_guard"
        })

        self.fitness = 2 if self.telemetry["expansion_trigger"] else 1
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
                            except Exception:
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
            except Exception:
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
        except Exception:
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
        self.cfg = self._load_config(config_path)
        self.policy = Policy(config=self.cfg)
        self.memory = QueenMemory()
        self.broodlings = []
        self.fitness_scores = {}
        self.colonies = []
        self.genetic_memory = []
        self.audit = Audit(root=".")
        self.storage = StorageV2(root=".", audit=self.audit)

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
        except Exception:
            pass

        for p in try_paths:
            try:
                with open(p) as f:
                    return json.load(f)
            except Exception:
                continue

        return {
            "cycle_seconds": 30,
            "startup_caps": {"per_broodling": {"cpu_pct": 0.5, "mem_mb": 8}},
            "stage_thresholds": {"juvenile": 50, "mature": 100, "elder": 150},
            "max_hatch_per_cycle": 2,
            "fitness": {"aggregation_mode": "average", "weighting": {}},
            "broodling_lifecycle": 125,
            "target_ip_range": "0.0.0.0/0",
        }

    def generate_tag(self):
        return f"BRD-{''.join(random.choices(string.ascii_uppercase + string.digits, k=6))}"

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

        # Feed environment telemetry into Policy
        env_telemetry = {
            "avg_cpu_pct": sum(b.telemetry.get("cpu_pct", 0) for b in self.broodlings) / max(1, len(self.broodlings)),
            "avg_mem_mb": sum(b.telemetry.get("mem_mb", 0) for b in self.broodlings) / max(1, len(self.broodlings)),
            "avg_io_wait": sum(b.telemetry.get("io_wait", 0) for b in self.broodlings) / max(1, len(self.broodlings)),
            "avg_latency_ms": sum(b.telemetry.get("latency_ms", 0) for b in self.broodlings) / max(1, len(self.broodlings)),
            "os_distribution": {
                k: sum(1 for b in self.broodlings if b.telemetry.get("os_type") == k)
                for k in ("linux", "windows", "macos")
            },
            "hive_size": len(self.broodlings)
        }

        try:
            if hasattr(self, 'policy') and self.policy:
                self.policy.adapt_to_environment(env_telemetry)
        except Exception:
            pass

        # Attempt scout-driven expansion
        try:
            self.expand_colony(ip_range=self.cfg.get("target_ip_range", "0.0.0.0/0"))
        except Exception:
            pass

        # Successor spawn at 299
        successor = None
        if self.global_cycle == self.replacement_cycle:
            successor = Queen()
            successor.genetic_memory = self.genetic_memory.copy()
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
                    except Exception:
                        pass
                self.broodlings.remove(b)
            try:
                if self.storage:
                    self.storage.checkpoint(self)
            except Exception:
                pass
            try:
                if self.audit:
                    self.audit.log_queen_state(self)
            except Exception:
                pass
            return successor

        # Save checkpoint + audit each cycle
        try:
            if self.storage:
                self.storage.checkpoint(self)
        except Exception:
            pass
        try:
            if self.audit:
                self.audit.log_queen_state(self)
        except Exception:
            pass

        print(f"Cycle {self.global_cycle} complete → {len(self.broodlings)} broodlings active")
        return successor

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
    return {"cycle_seconds": 30, "use_logging": False}


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