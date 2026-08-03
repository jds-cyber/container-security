from pathlib import Path
from jinja2 import Environment, FileSystemLoader


def generate_report(summary, output):

    template_dir = Path(__file__).parent / "templates"

    env = Environment(
        loader=FileSystemLoader(template_dir)
    )

    template = env.get_template(
        "report.html.j2"
    )

    html = template.render(
        summary=summary
    )

    Path(output).write_text(html)
