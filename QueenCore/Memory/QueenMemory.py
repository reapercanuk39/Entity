# QueenCore/Memory/QueenMemory.py

import json
import os
import itertools

try:
    from QueenCore.Modules import TRAIT_DEFINITIONS
except Exception:
    TRAIT_DEFINITIONS = {}


class QueenMemory:
    """
    Adaptive genetic memory and lifecycle manager.
    - Config-driven thresholds and decay
    - Generalized trait inheritance across categories
    - Lifecycle registration, age tracking, retirement automation
    - Trait scoring, promotion, decay, and fusion
    - Error penalties with resilience trait spawning
    - Persistent lineage file with cycle summaries
    """

    def __init__(self, lineage_file="modules/lineage.json", config=None):
        # Configurable parameters
        self.config = config or {
            "promotion_threshold": 10,
            "decay_rate": 1,
            "fusion_threshold": 3
        }

        # Trait memory
        self.trait_scores = {}        # cumulative scores for all traits
        self.lineage_traits = set()   # promoted traits

        # Lifecycle memory
        self.lineage_age = {}         # brood_tag -> age_cycles
        self.max_cycles = {}          # brood_tag -> max_cycles

        # Global cycle counter
        self.global_cycle = 0

        # Persistent lineage file
        self.lineage_file = lineage_file
        if not os.path.exists(self.lineage_file):
            with open(self.lineage_file, "w") as f:
                json.dump({"traits": {}, "errors": {}, "cycles": []}, f)

    # -------------------------
    # Persistence helpers
    # -------------------------
    def _load(self):
        with open(self.lineage_file, "r") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.lineage_file, "w") as f:
            json.dump(data, f, indent=2)

    def _append_cycle_summary(self, summary):
        data = self._load()
        data.setdefault("cycles", []).append(summary)
        self._save(data)

    def apply_error_penalties(self, error_snippet_path):
        """
        Adjust lineage traits based on error logs:
        - Increment error counters
        - Reduce fitness scores
        - Spawn resilience traits for critical errors
        """
        if not os.path.exists(error_snippet_path):
            print(f"[QueenMemory] No error snippet found at {error_snippet_path}")
            return

        with open(error_snippet_path, "r") as f:
            entries = json.load(f)

        data = self._load()

        for e in entries:
            sev = e["severity"]
            src = e["source"]

            # track error counts
            data["errors"].setdefault(src, {})
            data["errors"][src][sev] = data["errors"][src].get(sev, 0) + 1

            # ensure trait record exists
            data["traits"].setdefault(src, {"fitness": 100, "resilience": 0})

            # apply penalties
            if sev == "error":
                penalty = 5
            elif sev == "critical":
                penalty = 10
            else:
                penalty = 2

            data["traits"][src]["fitness"] = max(
                0, data["traits"][src]["fitness"] - penalty
            )

            # spawn resilience trait if critical
            if sev == "critical":
                data["traits"][src]["resilience"] += 1
                self.lineage_traits.add("resilience")
                print(f"[QueenMemory] {src} gained resilience trait (+1) due to critical error")

        self._save(data)
        print(f"[QueenMemory] Applied penalties and trait evolution from {len(entries)} error entries")

    # -------------------------
    # Lifecycle management
    # -------------------------
    def register_broodling(self, broodling, max_cycles):
        self.lineage_age[broodling.tag] = 0
        self.max_cycles[broodling.tag] = int(max_cycles)

    def tick_broodling(self, broodling):
        self.lineage_age[broodling.tag] = self.lineage_age.get(broodling.tag, 0) + 1

    def get_age(self, broodling):
        return self.lineage_age.get(broodling.tag, 0)

    def should_retire(self, broodling):
        return self.get_age(broodling) >= self.max_cycles.get(broodling.tag, 0)

    def retire_broodlings(self, broodlings):
        """Return broodlings that should continue (filter out retired)."""
        return [b for b in broodlings if not self.should_retire(b)]

    # -------------------------
    # Trait scoring & lineage
    # -------------------------
    def record_success(self, trait_name, score=1):
        self.trait_scores[trait_name] = self.trait_scores.get(trait_name, 0) + score
        if self.trait_scores[trait_name] >= self.config["promotion_threshold"]:
            self.lineage_traits.add(trait_name)

    def record_failure(self, trait_name):
        self.trait_scores[trait_name] = max(0, self.trait_scores.get(trait_name, 0) - 1)

    def absorb_trait(self, trait, brood_tag=None):
        self.lineage_traits.add(str(trait))

    def inherit_traits(self, broodling):
        existing = set(getattr(broodling, "traits", []))

        # Direct lineage traits
        existing.update(self.lineage_traits)

        # Advanced traits across all categories
        for category, traits in TRAIT_DEFINITIONS.items():
            for trait_name, trait_def in traits.items():
                evolves_from = trait_def.get("evolves_from")
                if not evolves_from:
                    continue
                if isinstance(evolves_from, list):
                    satisfied = all(t in self.lineage_traits for t in evolves_from)
                else:
                    satisfied = evolves_from in self.lineage_traits
                if satisfied:
                    existing.add(trait_name)

        broodling.traits = list(existing)
        return list(existing)

    def absorb_from_broodlings(self, broodlings):
        for b in broodlings:
            for category, traits in TRAIT_DEFINITIONS.items():
                for trait, trait_def in traits.items():
                    if trait in getattr(b, "traits", []):
                        eval_fn = trait_def.get("eval")
                        score = 0
                        if callable(eval_fn):
                            try:
                                score = eval_fn(b, None)
                            except Exception:
                                score = 0
                        self.trait_scores[trait] = self.trait_scores.get(trait, 0) + score

    def promote_lineage(self):
        for trait, score in self.trait_scores.items():
            if score >= self.config["promotion_threshold"]:
                self.lineage_traits.add(trait)

    def decay_traits(self):
        """Gradually reduce scores for unused traits."""
        for trait in list(self.trait_scores.keys()):
            self.trait_scores[trait] = max(
                0, self.trait_scores[trait] - self.config["decay_rate"]
            )

    def fuse_traits(self):
        """Create fusion traits when lineage traits consistently co-occur."""
        combos = itertools.combinations(sorted(self.lineage_traits), 2)
        for a, b in combos:
            fusion_name = f"{a}_{b}_fusion"
            if fusion_name not in self.lineage_traits:
                if self.trait_scores.get(a, 0) >= self.config["fusion_threshold"] and \
                   self.trait_scores.get(b, 0) >= self.config["fusion_threshold"]:
                    self.lineage_traits.add(fusion_name)

    # -------------------------
    # Cycle orchestration
    # -------------------------
    def tick_all(self, broodlings):
        self.global_cycle += 1
        results = {}
        fitnesses = []
        ips_total, ports_total = 0, 0

        broodlings = self.retire_broodlings(broodlings)

        for b in broodlings:
            fitness, report = b.tick()
            results[b.tag] = {"fitness": fitness, "telemetry": report}
            try:
                fitnesses.append(float(fitness))
            except Exception:
                fitnesses.append(0.0)

            if "ip_ranges" in report:
                ips_total += len(report["ip_ranges"])
            if "open_ports" in report:
                ports_total += len(report["open_ports"])

            self.tick_broodling(b)

        avg_fitness = float(sum(fitnesses)) / max(1, len(broodlings))

        summary = {
            "cycle": self.global_cycle,
            "population": len(broodlings),
            "avg_fitness": avg_fitness,
            "ips_discovered_total": ips_total,
            "open_ports_total": ports_total,
            "diversity_index": len(set(tuple(sorted(b.traits)) for b in broodlings)),
            "innovations": len(self.lineage_traits)
        }
        results["_summary"] = summary

        self.absorb_from_broodlings(broodlings)
        self.promote_lineage()
        self.decay_traits()
        self.fuse_traits()
        self._append_cycle_summary(summary)

        return results

    # -------------------------
    # Accessors
    # ----------------