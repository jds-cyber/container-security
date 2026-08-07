import plotly.express as px
import plotly.io as pio
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from lib.trends import load_history
from lib.comparison import compare_scores, compare_vulnerabilities


def severity_bar_chart(summary):
    data = {
        "Severity": [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Negligible",
            "Unknown",
        ],
        "Count": [
            summary["critical"],
            summary["high"],
            summary["medium"],
            summary["low"],
            summary["negligible"],
            summary["unknown"],
        ],
    }

    fig = px.bar(
        data,
        x="Severity",
        y="Count",
        title="Vulnerability Severity",
    )

    return pio.to_html(
        fig,
        full_html=False,
        include_plotlyjs="cdn",
    )


def severity_pie_chart(summary):

    data = {
        "Severity": [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Negligible",
        ],
        "Count": [
            summary["critical"],
            summary["high"],
            summary["medium"],
            summary["low"],
            summary["negligible"],
        ],
    }

    fig = px.pie(
        data,
        names="Severity",
        values="Count",
        title="Severity Distribution",
    )

    return pio.to_html(
        fig,
        full_html=False,
        include_plotlyjs=False,
    )


def security_score_trend():
    """
    Build a security score trend.
    """

    history = load_history()

    if not history:
        return ""

    scores = [
        report["security_score"]
        for report in history
    ]

    x = [
        report["scan"]
        for report in history
    ]

    fig = px.line(
        x=x,
        y=scores,
        labels={
            "x": "Scan",
            "y": "Security Score"
        },
        markers=True,
        title="Security Score Trend"
    )

    return fig.to_html(
        full_html=False,
        include_plotlyjs=False
    )


def generate_report(summary, output, image_name="Unknown", previous_summary=None):

    template_dir = Path(__file__).parent / "templates"

    env = Environment(
        loader=FileSystemLoader(template_dir)
    )

    comparison = security_comparison(previous_summary, summary)

    template = env.get_template("report.html.j2")

    html = template.render(
        summary=summary,
        image=image_name,
        comparison=comparison,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        passed=summary["critical"] == 0,
        bar_chart=severity_bar_chart(summary),
        pie_chart=severity_pie_chart(summary),
        trend_chart=security_score_trend(),
    )

    Path(output).write_text(html)


def security_comparison(previous, current):
    """
    Build security comparison data between two scans.
    """

    if previous is None:
        return None

    score_comparison = compare_scores(previous, current)
    vulnerability_comparison = compare_vulnerabilities(previous, current)

    return {
        "score": score_comparison,
        "vulnerabilities": vulnerability_comparison
    }
