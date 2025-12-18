# Fitness.py
from collections import Counter

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
