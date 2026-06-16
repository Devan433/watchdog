from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Finding:
    check_name: str        # e.g. "Content-Security-Policy"
    category: str          # e.g. "headers", "ssl", "cors"
    passed: bool           # True = no issue found
    severity: str          # "critical", "high", "medium", "low", "info"
    detail: str            # what was found e.g. "CSP header is missing"
    fix: str               # copy-paste fix prompt for Cursor/Claude
    evidence: Optional[str] = None  # actual value found e.g. the raw header value

@dataclass
class ScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 0         # 0-100, higher is safer
    grade: str = ""        # A, B, C, D, F
    summary: str = ""      # one line e.g. "3 critical issues found"
    error: Optional[str] = None  # if the scan itself failed