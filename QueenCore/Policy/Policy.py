# QueenCore/Policy/Policy.py

import json
from QueenCore.Audit import Audit
from QueenCore.Telemetry import Telemetry
from QueenCore.Fitness import Fitness, update_fitness
from QueenCore.Memory.QueenMemory import GeneticMemory

audit = Audit(root=".")

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

        # Hooks into QueenCore subsystems
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
