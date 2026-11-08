# -*- coding: utf-8 -*-
"""
Process & Resource Intelligence Package.
Provides deep introspection of active Windows processes, in-memory loaded modules,
Restart Manager file locks, and service-to-process mappings.
"""

from .file_usage_inspector import FileUsageInspector
from .process_inventory import ProcessInventory
from .module_inventory import ModuleInventory
from .service_process_mapper import ServiceProcessMapper

__all__ = [
    "FileUsageInspector",
    "ProcessInventory",
    "ModuleInventory",
    "ServiceProcessMapper"
]
