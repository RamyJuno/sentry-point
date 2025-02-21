# core/data_types.py

from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Host:
    ip_address: str
    hostname: Optional[str] = None
    open_ports: List[int] = None

@dataclass
class Vulnerability:
    cve_id: str
    description: str
    severity: str  # "Low", "Medium", "High", "Critical"
    evidence: Optional[str] = None

@dataclass
class SSLInfo:
    issuer: str
    subject: str
    valid_from: str
    valid_to: str
    grade: str

@dataclass
class BreachRecord:
    email: str
    breach_name: str
    date: str
    exposed_data: Optional[str] = None
