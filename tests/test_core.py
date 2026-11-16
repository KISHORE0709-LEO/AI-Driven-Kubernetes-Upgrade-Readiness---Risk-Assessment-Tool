import json
from pathlib import Path

from kubernetes_upgrade_assessor.core import assess_cluster, generate_assessment_report


def load_sample_data():
    with Path(__file__).resolve().parents[1].joinpath("examples", "sample_cluster_data.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_assessment_reports_known_risk():
    sample = load_sample_data()
    assessment = assess_cluster(sample, "1.25", "1.29")
    assert assessment["decision"] == "NOT RECOMMENDED"
    assert assessment["readiness_score"] <= 100
    assert assessment["confidence_score"] <= 100
    assert len(assessment["verified_issues"]) >= 1
    assert "WHAT WILL BREAK" in generate_assessment_report(assessment)


def test_report_contains_required_sections():
    sample = load_sample_data()
    assessment = assess_cluster(sample, "1.25", "1.29")
    report = generate_assessment_report(assessment)
    for required in [
        "UPGRADE DECISION:",
        "READINESS SCORE:",
        "CONFIDENCE:",
        "Risk Matrix",
        "## Verified Issues",
        "## Probable Issues",
        "## Possible Issues",
        "## Unknown Risks",
        "WHAT WILL BREAK:",
    ]:
        assert required in report
