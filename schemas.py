from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

class ProviderFinding(BaseModel):
    provider: str
    reputation: Optional[str] = None  # e.g., malicious/suspicious/clean/unknown
    score: Optional[float] = None     # normalized 0..100
    categories: List[str] = []
    references: List[str] = []
    raw: Dict = {}

class EnrichedIOC(BaseModel):
    indicator: str
    ioc_type: str  # ip/domain/url/hash/unknown
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = []
    findings: List[ProviderFinding] = []

class EngineReport(BaseModel):
    generated_at: datetime
    total: int
    by_type: Dict[str, int]
    enrichments: List[EnrichedIOC]
