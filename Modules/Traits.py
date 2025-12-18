# Queen/Modules/Traits.py

"""
Traits.py
---------
Defines evolutionary trait progression for hive broodlings.
Includes:
- TRAIT_DEFINITIONS: hierarchical trait metadata
- TraitEngine: evaluation and evolution logic
"""

from typing import Dict, Any


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