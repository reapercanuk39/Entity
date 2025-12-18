# QueenCore/Modules/Broodlings.py

import random
try:
    from .Snippets.Base_Broodling import BroodlingBase
except ImportError:
    from QueenCore.Modules.Snippets import BroodlingBase

try:
    from .audit import Audit
except ImportError:
    try:
        from ..hive.audit import Audit
    except ImportError:
        from hive.audit import Audit

audit = Audit(root='.')


class Scout(BroodlingBase):
    def tick(self, ip_range=None, ports=None, **kwargs):
        # Multi-range probe telemetry
        self.telemetry["ip_ranges"] = ip_range or ["192.168.0.0/24", "10.0.0.0/24"]

        # Port scan telemetry
        open_ports, blocked_ports = [], []
        for port in (ports or [22, 80, 443]):
            if random.random() < 0.2:
                open_ports.append(port)
            else:
                blocked_ports.append(port)
        self.telemetry["open_ports"] = open_ports
        self.telemetry["blocked_ports"] = blocked_ports

        # Resource telemetry
        self.telemetry["cpu_pct"] = random.uniform(10, 90)
        self.telemetry["ram_pct"] = random.uniform(10, 90)
        self.telemetry["io_wait"] = random.uniform(0, 50)

        # Environment telemetry
        self.telemetry["latency_ms"] = random.randint(10, 300)
        self.telemetry["os_type"] = random.choice(["linux", "windows", "macos"])

        # Stealth flags
        self.apply_trait_flags(["timing_obfuscation", "signal_masking", "low_signature_scan"])

        # Trait fusion
        self.apply_trait_fusion({
            ("network_probe", "stealth_mode"): "ghost_probe"
        })

        # Fitness calculation
        self.fitness = len(open_ports) * 2 + len(self.telemetry["ip_ranges"])
        self.cycle += 1

        # Audit logging
        if "multi_range_probe" in self.traits:
            audit.log_trait_activity(self, "multi_range_probe", f"Ranges={self.telemetry['ip_ranges']}")
            try:
                audit.log_ip_check(self, self.telemetry['ip_ranges'])
            except Exception:
                pass
        if "port_scan" in self.traits:
            audit.log_trait_activity(self, "port_scan", f"Open={open_ports}, Blocked={blocked_ports}")
            try:
                audit.log_port_check(self, open_ports, blocked_ports)
            except Exception:
                pass
        if self.fused_traits:
            audit.log_trait_fusion(self, self.fused_traits, ["network_probe", "stealth_mode"])

        return self.fitness, self.telemetry


class Scanner(BroodlingBase):
    def tick(self, ports=None, **kwargs):
        scanned_ports = ports or [22, 80, 443]
        open_ports = [p for p in scanned_ports if random.random() < 0.3]
        blocked_ports = [p for p in scanned_ports if p not in open_ports]

        self.telemetry["scanned_ports"] = scanned_ports
        self.telemetry["open_ports"] = open_ports
        self.telemetry["blocked_ports"] = blocked_ports

        self.apply_trait_flags(["low_signature_scan"])

        self.fitness = len(open_ports) * 2
        self.cycle += 1

        audit.log_trait_activity(self, "scanner", f"Scanned={scanned_ports}, Open={open_ports}")
        try:
            audit.log_port_check(self, open_ports, blocked_ports)
        except Exception:
            pass
        return self.fitness, self.telemetry


class Defender(BroodlingBase):
    def tick(self, **kwargs):
        blocked_ports = random.sample(range(20, 1024), random.randint(0, 5))
        self.telemetry["blocked_ports"] = blocked_ports
        self.telemetry["cpu_pct"] = random.uniform(5, 50)
        self.telemetry["ram_pct"] = random.uniform(5, 50)
        self.telemetry["io_wait"] = random.uniform(0, 20)

        self.fitness = len(blocked_ports)
        self.cycle += 1

        if "firewall_awareness" in self.traits:
            audit.log_trait_activity(self, "firewall_awareness", f"Blocked={blocked_ports}")

        try:
            audit.log_port_check(self, [], blocked_ports)
        except Exception:
            pass

        return self.fitness, self.telemetry


class Builder(BroodlingBase):
    def tick(self, **kwargs):
        resources_built = random.choice(["node", "link", "cache", "relay"])
        self.telemetry["resources_built"] = resources_built
        self.telemetry["expansion_trigger"] = random.choice([True, False])

        self.apply_trait_fusion({
            ("trait_fusion", "builder"): "builder_guard"
        })

        self.fitness = 2 if self.telemetry["expansion_trigger"] else 1
        self.cycle += 1

        audit.log_trait_activity(self, "builder", f"Built={resources_built}, Expansion={self.telemetry['expansion_trigger']}")
        return self.fitness, self.telemetry
