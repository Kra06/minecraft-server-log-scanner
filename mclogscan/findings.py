#The Finding data model shared by signature rules and behavioural detectors

#scanner needs to write down the details of an attack when one happens
#this file outlines the class for the finding objects which are created every time attack is found


from __future__ import annotations

from dataclasses import asdict, dataclass, field    #tools for making forms
from datetime import datetime
from typing import List, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")              #tuple of how serious an attack is
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}    #severity given a number so can be filtered


@dataclass
class Finding:
    rule_id: str                        
    name: str                           
    severity: str
    category: str
    description: str
    timestamp: datetime
    source: str
    line_no: int
    evidence: str
    player: Optional[str] = None 
    ip: Optional[str] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict:          #converting to JSON format
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


