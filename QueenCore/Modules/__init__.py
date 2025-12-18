# QueenCore/Modules/__init__.py
TRAIT_DEFINITIONS = {
    "adaptability": {
        # example trait definitions
        "network_resilience": {
            "evolves_from": ["error_handling"],
            "eval": lambda broodling, _: broodling.fitness * 0.1
        },
        "error_handling": {
            "evolves_from": None,
            "eval": lambda broodling, _: 1 if "errors" in broodling.telemetry else 0
        }
    }
    # add other categories here
}
