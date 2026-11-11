# -*- coding: utf-8 -*-
"""
Bintra Registry Intelligence Engine.
Provides a structured 11-domain Windows registry catalog, dual 32-bit and 64-bit
view reading (KEY_WOW64_32KEY / KEY_WOW64_64KEY), and configuration anomaly analysis.
"""

from .registry_catalog import RegistryCatalog, RegistryKeySpec
from .registry_reader import WindowsRegistryReader
from .registry_analyzer import WindowsRegistryAnalyzer

__all__ = [
    "RegistryCatalog",
    "RegistryKeySpec",
    "WindowsRegistryReader",
    "WindowsRegistryAnalyzer"
]
