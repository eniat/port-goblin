import io

from rich.console import Console

from portgoblin.output import art
from portgoblin.output.terminal import art_banner, art_lines, report_text


def test_art_fits_its_declared_width():
    assert all(len(line) <= art.ART_WIDTH for line in art.GOBLIN_DOOR)
    assert art.is_door(5, art.DOOR_COLUMN)
    assert all(c < art.DOOR_COLUMN for _, c in art.KNOCK_CELLS)
    # Every knock and peeker cell holds part of the drawing.
    cells = list(art.KNOCK_CELLS) + [
        (r, c) for r in range(9, 17) for c in range(38, 44) if art.is_peeker(r, c)
    ]
    assert all(art.GOBLIN_DOOR[r][c] != " " for r, c in art.KNOCK_CELLS)
    assert any(art.GOBLIN_DOOR[r][c] != " " for r, c in cells)


def test_layout_by_width():
    wide = [line.plain for line in art_lines(140)]
    assert any("8888888b." in line and ".d8888b." in line for line in wide)  # one-line title
    medium = [line.plain for line in art_lines(100)]
    title_starts = [line[art.ART_WIDTH + 2 :] for line in medium]
    assert sum(t.startswith("8888888b.") for t in title_starts) == 1  # "Port" once
    assert any(".d8888b." in line for line in medium)  # Goblin on its own lines
    narrow = [line.plain for line in art_lines(60)]
    assert narrow and not any("888" in line for line in narrow)
    assert art_lines(40) == []
    assert all(len(line) <= 100 for line in medium)


def test_plain_banner_when_not_a_colour_terminal():
    buffer = io.StringIO()
    art_banner(Console(file=buffer, width=140, color_system=None, force_terminal=False))
    assert buffer.getvalue().strip() == "PortGoblin 0.1.0 | Knocking on every door"


def test_art_on_a_colour_terminal():
    buffer = io.StringIO()
    art_banner(Console(file=buffer, width=140, force_terminal=True, color_system="truecolor"))
    assert "⣿" in buffer.getvalue()  # braille block from the goblin


def test_saved_reports_never_contain_the_art():
    from portgoblin.core.models import Report, ScanResult

    text = report_text(Report(source="import", scan=ScanResult()))
    assert "⣿" not in text
