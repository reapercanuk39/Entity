import json
from typing import Dict, Any, List

class HiveConfig:
    def __init__(self, config_path: str = "QueenCore/Config/queen_config.json"):
        # Load Queen's orchestration policy
        with open(config_path, "r") as f:
            self.config: Dict[str, Any] = json.load(f)

    def get_caps(self, role: str = None) -> Dict[str, Any]:
        """Return resource caps, optionally role-specific."""
        caps = self.config["startup_caps"]["per_broodling"].copy()
        if role and "role_scaling" in self.config:
            scaling = self.config["role_scaling"].get(role, {})
            caps["cpu_pct"] += scaling.get("cpu_pct_bonus", 0)
            caps["mem_mb"] += scaling.get("mem_mb_bonus", 0)
        return caps

    def assign_traits(self, role: str) -> List[str]:
        """Assign trait bundle based on hatch role."""
        bundles = self.config.get("hatch_roles_traits", {})
        return bundles.get(role, [])

    def fitness_score(self, metrics: Dict[str, float]) -> float:
        """Compute fitness score using aggregation + weighting."""
        mode = self.config["fitness"]["aggregation_mode"]
        weights = self.config["fitness"].get("weighting", {})
        auto_adjust = self.config["fitness"].get("auto_adjust", False)

        if mode == "average":
            if weights:
                score = sum(metrics[k] * weights.get(k, 0) for k in metrics) / sum(weights.values())
            else:
                score = sum(metrics.values()) / len(metrics)
        else:
            score = sum(metrics.values())

        if auto_adjust:
            if metrics.get("colonies_spawned", 0) < 2:
                weights["innovation_events"] = weights.get("innovation_events", 0.3) + 0.1

        return score

    def stage(self, score: float) -> str:
        """Determine broodling stage based on thresholds."""
        thresholds = self.config["stage_thresholds"]
        if score >= thresholds["elder"]["score"]:
            return "elder"
        elif score >= thresholds["mature"]["score"]:
            return "mature"
        elif score >= thresholds["juvenile"]["score"]:
            return "juvenile"
        return "hatchling"

    def quarantine_cycles(self, traits: List[str]) -> int:
        """Adaptive quarantine length based on diagnostic traits."""
        q = self.config["quarantine"]
        if q["cycles"] == "adaptive":
            if "resource_awareness" in traits and "firewall_awareness" in traits:
                return q["min_cycles"]
            return q["max_cycles"]
        return q["cycles"]

    def hatch(self, role: str, metrics: Dict[str, float]) -> Dict[str, Any]:
        """Instantiate a broodling with role, traits, caps, fitness, stage, and quarantine cycles."""
        traits = self.assign_traits(role)
        caps = self.get_caps(role)
        score = self.fitness_score(metrics)
        stage = self.stage(score)
        quarantine = self.quarantine_cycles(traits)

        return {
            "role": role,
            "traits": traits,
            "caps": caps,
            "fitness_score": score,
            "stage": stage,
            "quarantine_cycles": quarantine
        }

# Example usage
if __name__ == "__main__":
    hive = HiveConfig()  # defaults to QueenCore/Config/queen_config.json
    broodling = hive.hatch(
        "scanner",
        {"innovation_events": 5, "colonies_spawned": 1, "resource_efficiency": 0.8}
    )
    print(broodling)
