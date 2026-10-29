import xml.etree.ElementTree as ET
from pathlib import Path


def test_poster_svg_parses_validly() -> None:
    svg_path = Path("docs/poster/poster.svg")
    assert svg_path.exists(), "docs/poster/poster.svg must exist"
    tree = ET.parse(svg_path)
    root = tree.getroot()
    assert "svg" in root.tag.lower()
    content = svg_path.read_text(encoding="utf-8")
    assert "ScaleDown Classify-1" in content
    assert "DESIGN ONLY / FUTURE WORK" in content
    assert "Jev" not in content


def test_poster_html_contains_required_sections() -> None:
    html_path = Path("docs/poster/poster.html")
    assert html_path.exists(), "docs/poster/poster.html must exist"
    content = html_path.read_text(encoding="utf-8")
    assert "ScaleDown Classify-1" in content
    assert "Zero delete verbs" in content or "Zero pod delete verbs" in content
    assert "AI-Assistance Disclosure" in content
    assert "Zero Data Retention" in content
    assert "Jev" not in content


def test_poster_diagrams_exist_and_clean() -> None:
    pipeline_diag = Path("docs/poster/diagrams/pipeline_flow.mermaid")
    policy_diag = Path("docs/poster/diagrams/decision_policy.mermaid")
    assert pipeline_diag.exists()
    assert policy_diag.exists()

    content_pipe = pipeline_diag.read_text(encoding="utf-8")
    content_policy = policy_diag.read_text(encoding="utf-8")

    assert "ScaleDown" in content_pipe
    assert "Jev" not in content_pipe
    assert "Jev" not in content_policy
