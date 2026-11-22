"""The action metadata must parse, and the root and nested copies must match."""
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROOT_ACTION = ROOT / "action.yml"
NESTED_ACTION = ROOT / ".github" / "actions" / "vu1nz-actions-scan" / "action.yml"


def load(path):
    return yaml.safe_load(path.read_text())


def test_root_action_parses_and_is_marketplace_ready():
    action = load(ROOT_ACTION)
    assert action["name"] == "vu1nz Actions Security Scan"
    assert action["description"]
    assert action["branding"]["icon"] and action["branding"]["color"]
    assert action["runs"]["using"] == "composite"


def test_nested_copy_matches_root():
    assert NESTED_ACTION.read_text() == ROOT_ACTION.read_text()


def test_run_scripts_have_no_expression_interpolation():
    for step in load(ROOT_ACTION)["runs"]["steps"]:
        assert "${{" not in step.get("run", ""), step.get("name")


def test_run_scripts_are_valid_shell_and_python():
    for step in load(ROOT_ACTION)["runs"]["steps"]:
        script = step.get("run")
        if not script:
            continue
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)
        for body in re.findall(r"<<'PY'\n(.*?)\nPY\n", script, re.S):
            compile(body, step["name"], "exec")
