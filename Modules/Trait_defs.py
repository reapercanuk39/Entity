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
