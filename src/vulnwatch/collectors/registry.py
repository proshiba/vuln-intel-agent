from __future__ import annotations

from vulnwatch.collectors.base import Collector
from vulnwatch.collectors.browser import BrowserCollector
from vulnwatch.collectors.csaf import CsafCollector
from vulnwatch.collectors.feed import FeedCollector
from vulnwatch.collectors.html import HtmlCollector
from vulnwatch.collectors.json_api import JsonApiCollector
from vulnwatch.collectors.osv import OsvCollector
from vulnwatch.collectors.pdf import PdfCollector
from vulnwatch.models import CollectorKind


def create_collector(kind: CollectorKind) -> Collector:
    if kind == CollectorKind.CSAF:
        return CsafCollector()
    if kind == CollectorKind.JSON_API:
        return JsonApiCollector()
    if kind == CollectorKind.FEED:
        return FeedCollector()
    if kind == CollectorKind.HTML:
        return HtmlCollector()
    if kind == CollectorKind.BROWSER:
        return BrowserCollector()
    if kind == CollectorKind.OSV:
        return OsvCollector()
    return PdfCollector()
