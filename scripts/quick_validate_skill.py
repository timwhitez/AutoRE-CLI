#!/usr/bin/env python3
"""Validate the public Auto-RE Skill metadata and required structure."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


NAME_PATTERN = re.compile(r"^[a-z0-9-]+$")
FRONTMATTER_PATTERN = re.compile(r"^---\n(.*?)\n---(?:\n|$)", re.DOTALL)
REQUIRED_FILES = {
    "SKILL.md",
    "agents/openai.yaml",
    "references/command-routing.md",
    "references/evidence-contract.md",
    "references/investigation-workflows.md",
    "references/safety-and-claims.md",
    "scripts/run_next_action.py",
    "scripts/verify_bundle.py",
}


class SkillValidationError(ValueError):
    pass


def parse_frontmatter(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            raise SkillValidationError(f"invalid SKILL.md frontmatter line: {line!r}")
        normalized_key = key.strip()
        if normalized_key in fields:
            raise SkillValidationError(
                f"duplicate SKILL.md frontmatter key: {normalized_key}"
            )
        fields[normalized_key] = value.strip().strip('"')
    return fields


def quoted_interface_value(text: str, key: str) -> str:
    match = re.search(
        rf'^\s{{2}}{re.escape(key)}:\s*"([^"\n]+)"\s*$',
        text,
        re.MULTILINE,
    )
    if match is None:
        raise SkillValidationError(
            f"agents/openai.yaml must contain quoted interface.{key}"
        )
    return match.group(1)


def validate_skill(skill_dir: pathlib.Path) -> dict[str, Any]:
    skill_dir = skill_dir.expanduser().resolve()
    skill_md = skill_dir / "SKILL.md"
    try:
        content = skill_md.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise SkillValidationError(f"cannot read SKILL.md: {error}") from error

    match = FRONTMATTER_PATTERN.match(content)
    if match is None:
        raise SkillValidationError("SKILL.md has invalid YAML frontmatter")
    frontmatter = parse_frontmatter(match.group(1))
    if set(frontmatter) != {"name", "description"}:
        raise SkillValidationError(
            "SKILL.md frontmatter must contain only name and description"
        )
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise SkillValidationError("Skill name must use lowercase hyphen-case")
    if len(name) > 64 or name.startswith("-") or name.endswith("-") or "--" in name:
        raise SkillValidationError("Skill name is not canonical")
    if not isinstance(description, str) or not description.strip():
        raise SkillValidationError("Skill description must be non-empty")
    if len(description) > 1024 or "<" in description or ">" in description:
        raise SkillValidationError("Skill description is invalid")

    actual_files = {
        path.relative_to(skill_dir).as_posix()
        for path in skill_dir.rglob("*")
        if path.is_file()
    }
    missing = sorted(REQUIRED_FILES - actual_files)
    if missing:
        raise SkillValidationError(f"Skill is missing required files: {missing}")

    openai_path = skill_dir / "agents/openai.yaml"
    openai_text = openai_path.read_text(encoding="utf-8")
    if not re.search(r"^interface:\s*$", openai_text, re.MULTILINE):
        raise SkillValidationError("agents/openai.yaml must contain interface")
    quoted_interface_value(openai_text, "display_name")
    short_description = quoted_interface_value(openai_text, "short_description")
    if not 25 <= len(short_description) <= 64:
        raise SkillValidationError("short_description must contain 25-64 characters")
    prompt = quoted_interface_value(openai_text, "default_prompt")
    if "$auto-re" not in prompt:
        raise SkillValidationError("default_prompt must mention $auto-re")

    if len(content.splitlines()) > 500:
        raise SkillValidationError("SKILL.md exceeds the 500-line entrypoint limit")

    return {
        "ok": True,
        "name": name,
        "description_length": len(description),
        "skill_file_count": len(actual_files),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("skill_dir", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    try:
        result = validate_skill(parse_args().skill_dir)
    except (SkillValidationError, OSError) as error:
        print(f"skill validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "skill validation passed: "
        f"name={result['name']} files={result['skill_file_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
