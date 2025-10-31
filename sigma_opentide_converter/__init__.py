"""
Sigma to OpenTide Converter

A CLI tool for converting Sigma detection rules to OpenTide MDR format.
Supports Microsoft Defender for Endpoint and Splunk configurations.
"""

__version__ = "1.0.0"
__author__ = "Detection Engineering Team"

from .converter import SigmaToOpenTideConverter

__all__ = ["SigmaToOpenTideConverter"]