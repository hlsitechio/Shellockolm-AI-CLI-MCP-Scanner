"""
Shellockolm Modular Scanner Architecture
Each scanner is independent and can be used standalone or combined
"""

from .base import BaseScanner, ScanResult, ScanFinding
from .react_rsc import ReactRSCScanner
from .nextjs import NextJSScanner
from .npm_packages import NPMPackageScanner
from .nodejs import NodeJSScanner
from .n8n import N8NScanner
from .supply_chain import SupplyChainScanner
from .clawdbot import ClawdbotScanner

__all__ = [
    'BaseScanner',
    'ScanResult',
    'ScanFinding',
    'ReactRSCScanner',
    'NextJSScanner',
    'NPMPackageScanner',
    'NodeJSScanner',
    'N8NScanner',
    'SupplyChainScanner',
    'ClawdbotScanner',
]

# Scanner registry for CLI
SCANNER_REGISTRY = {
    'react': ReactRSCScanner,
    'nextjs': NextJSScanner,
    'npm': NPMPackageScanner,
    'nodejs': NodeJSScanner,
    'n8n': N8NScanner,
    'supply-chain': SupplyChainScanner,
    'clawdbot': ClawdbotScanner,
}

def get_all_scanners():
    """Get instances of all available scanners"""
    return [scanner_class() for scanner_class in SCANNER_REGISTRY.values()]

def get_scanner(name: str):
    """Get a specific scanner by name"""
    if name not in SCANNER_REGISTRY:
        raise ValueError(f"Unknown scanner: {name}. Available: {list(SCANNER_REGISTRY.keys())}")
    return SCANNER_REGISTRY[name]()
