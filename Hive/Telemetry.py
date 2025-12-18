# QueenCore/Hive/Telemetry.py

from Modules.Trait_defs import TRAIT_DEFS

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
