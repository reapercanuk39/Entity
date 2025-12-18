import random
import string
import json
import os
from collections import Counter

from .hive.audit import Audit
from .hive.storage import Storage
from .policy import Policy
from .modules.traits import TRAIT_DEFINITIONS
from .QueenMemory import QueenMemory
from .modules.broodlings import Scout, Scanner, Defender, Builder
from .modules.snippets.base_broodling import BroodlingBase


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
        self.storage = Storage(root=".", audit=self.audit)

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
        new_queen.genetic_memory = self.genetic_memory.copy()

        travel_traits = ["ssh_hop", "adb_tunnel"]
        for trait in travel_traits:
            if trait not in new_queen.genetic_memory:
                new_queen.genetic_memory.append(trait)

        print(f"Juvenile Queen spawned at {ip_range} with traits: {new_queen.genetic_memory}")
        if self.audit:
            self.audit.log("expansion", {"ip_range": ip_range, "traits": new_queen.genetic_memory, "telemetry": discovered})

        self.colonies.append({"ip_range": ip_range, "queen": new_queen})
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
