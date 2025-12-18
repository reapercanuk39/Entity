# QueenCore/Modules/Dashboard.py

import time
import logging
import json
import os

try:
    from .queen import Queen
except Exception:
    # fallback for direct script execution
    from queen import Queen


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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\n🐝 Hive simulation stopped gracefully.")
