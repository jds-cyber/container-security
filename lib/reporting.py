from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def generate_report(summary, output, image_name="Unknown"):

    template_dir = Path(__file__).parent / "templates"

    env = Environment(
        loader=FileSystemLoader(template_dir)
    )

    template = env.get_template("report.html.j2")

    html = template.render(
        summary=summary,
        image=image_name,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        passed=summary["critical"] == 0
    )

    Path(output).write_text(html)
