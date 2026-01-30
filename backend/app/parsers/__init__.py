"""Vendor-specific rule parsers."""

from app.parsers.base import BaseParser, ParsedRule
from app.parsers.sigma import SigmaParser
from app.parsers.elastic import ElasticParser
from app.parsers.splunk import SplunkParser
from app.parsers.sublime import SublimeParser
from app.parsers.elastic_protections import ElasticProtectionsParser
from app.parsers.lolrmm import LOLRMMParser
from app.parsers.elastic_hunting import ElasticHuntingParser
from app.parsers.sentinel import SentinelParser

__all__ = [
    "BaseParser",
    "ParsedRule",
    "SigmaParser",
    "ElasticParser",
    "SplunkParser",
    "SublimeParser",
    "ElasticProtectionsParser",
    "LOLRMMParser",
    "ElasticHuntingParser",
    "SentinelParser",
]
