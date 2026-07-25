"""
Program scope extractors.

Each extractor takes a handle or URL and produces a ``ProgramScope``.
They are kept zero-dependency on each other and share only the data
model + the LLM helper, so a buggy adapter for one platform can't
regress the others.

Public surface:
    from core.intel.extractors import Extractor, ExtractorError
    from core.intel.extractors import GenericUrlExtractor
    from core.intel.extractors import HackerOneExtractor, BugcrowdExtractor
"""
from __future__ import annotations

from core.intel.extractors.base import Extractor, ExtractorError
from core.intel.extractors.bugcrowd import BugcrowdExtractor
from core.intel.extractors.generic_url import GenericUrlExtractor
from core.intel.extractors.hackerone import HackerOneExtractor

__all__ = [
    "Extractor",
    "ExtractorError",
    "GenericUrlExtractor",
    "HackerOneExtractor",
    "BugcrowdExtractor",
]
