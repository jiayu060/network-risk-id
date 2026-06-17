"""Factory to load parsers by source type."""

from src.parsers.base import LogParser
from src.parsers.syslog_parser import SyslogParser
from src.parsers.dns_parser import DNSParser
from src.parsers.waf_parser import WAFParser
from src.parsers.etw_parser import ETWParser


class ParserRegistry:
    """Registry of log parsers keyed by source_type."""

    _parsers: dict[str, type] = {
        "syslog": SyslogParser,
        "dns": DNSParser,
        "waf": WAFParser,
        "etw": ETWParser,
    }

    @classmethod
    def register(cls, source_type: str, parser_cls: type):
        """Register a new parser class."""
        if not issubclass(parser_cls, LogParser):
            raise TypeError(f"{parser_cls} must implement LogParser")
        cls._parsers[source_type] = parser_cls

    @classmethod
    def get_parser(cls, source_type: str, **kwargs) -> LogParser:
        """Get a parser instance for the given source type."""
        if source_type not in cls._parsers:
            raise ValueError(f"No parser registered for source_type='{source_type}'. Available: {list(cls._parsers)}")
        return cls._parsers[source_type](**kwargs)

    @classmethod
    def available_parsers(cls) -> list[str]:
        return list(cls._parsers.keys())
