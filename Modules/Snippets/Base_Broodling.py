#QueenCore/Modules/Snippets/Base_Broodling.py

class BroodlingBase:
    """
    Base broodling template. The Queen uses this to hatch any broodling type
    (scout, scanner, defender, builder, etc.) by assigning a role and traits.
    """

    def __init__(self, tag, role="scout", traits=None):
        self.tag = tag
        self.role = role
        self.traits = traits or []
        self.telemetry = {}
        self.fitness = 0.0
        self.cycle = 0
        self.fused_traits = None

    def tick(self, **kwargs):
        """
        Generic tick behavior. Specialized broodlings override this.
        Returns (fitness, telemetry).
        """
        return self.fitness, self.telemetry

    def fitness_report(self):
        """Return the latest telemetry for trait evaluation."""
        return self.telemetry
