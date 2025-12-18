# Storage.py v2
# ----------------
# Handles checkpointing and restoration of hive state.
# Captures hive stats, fitness landscape, broodling traits, and genetic memory.

import os
import json
import tempfile
import time
from queen.modules.Traits import TRAIT_DEFINITIONS


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
