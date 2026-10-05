from datetime import date
from pathlib import Path

import pytest

from mclogscan.parser import parse_lines

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


@pytest.fixture
def parse():
    """Parse log text into a list of LogEntry objects on a fixed date."""

    def _parse(text: str):
        return list(parse_lines(text.strip().splitlines(), base_date=date(2026, 9, 20)))

    return _parse


@pytest.fixture
def attack_log() -> Path:
    return SAMPLES / "attack-2026-09-20.log"


@pytest.fixture
def clean_log() -> Path:
    return SAMPLES / "clean-2026-09-21.log"
