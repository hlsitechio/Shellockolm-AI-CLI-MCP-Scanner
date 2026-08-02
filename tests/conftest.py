"""
Pytest configuration for Shellockolm.

The source uses a FLAT import layout (e.g. `import compat`,
`from scanners import ...`, `from vulnerability_database import ...`) with no
`shellockolm.` namespace package. To exercise the modules in-tree (without
requiring an editable install) we prepend src/ to sys.path here so the flat
imports resolve from every test module.
"""

import os
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
