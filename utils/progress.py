from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn


@contextmanager
def scan_progress() -> Generator[Progress, None, None]:
    """스캔 진행 상태를 표시하는 컨텍스트 매니저."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
    ) as progress:
        yield progress
