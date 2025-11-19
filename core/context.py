from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional


@dataclass
class ReconContext:
    domain: str
    store: bool = False
    output_dir: Optional[Path] = None
    threads: int = 10
    version: str = "3.0.0"

    results: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def ensure_output_dir(self) -> None:
        if self.store and self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
