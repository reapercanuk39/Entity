"""
Snippets package for QueenCore.
Provides base broodling templates and other snippet modules.
"""

from .Base_Broodling import BroodlingBase

# Future broodling types (add as you implement them)
try:
    from .Scout_Broodling import ScoutBroodling
except ImportError:
    ScoutBroodling = None

try:
    from .Defender_Broodling import DefenderBroodling
except ImportError:
    DefenderBroodling = None

try:
    from .Builder_Broodling import BuilderBroodling
except ImportError:
    BuilderBroodling = None

try:
    from .Scanner_Broodling import ScannerBroodling
except ImportError:
    ScannerBroodling = None

__all__ = [
    "BroodlingBase",
    "ScoutBroodling",
    "DefenderBroodling",
    "BuilderBroodling",
    "ScannerBroodling",
]
