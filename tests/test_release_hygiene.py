import json
import os

FORBIDDEN = ("FGUARD" + "2024!", "FGuard" + "2024!")
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "iso-work"}


def test_readme_version_matches_version_json():
    with open("version.json", "r", encoding="utf-8") as handle:
        version = json.load(handle)["version"]
    with open("README.md", "r", encoding="utf-8") as handle:
        readme = handle.read()
    assert "**v%s**" % version in readme


def test_published_root_password_is_not_in_the_tree():
    found = []
    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
            except (UnicodeDecodeError, OSError):
                continue
            for secret in FORBIDDEN:
                if secret in text:
                    found.append(path)
    assert found == []
