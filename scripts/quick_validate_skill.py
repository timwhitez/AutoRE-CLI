#!/usr/bin/env python3
"""Validate the public Auto-RE Skill metadata and required structure."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any


NAME_PATTERN = re.compile(r"^[a-z0-9-]+$")
FRONTMATTER_PATTERN = re.compile(r"^---\n(.*?)\n---(?:\n|$)", re.DOTALL)
REQUIRED_FILES = {
    "VERSION",
    "SKILL.md",
    "agents/openai.yaml",
    "evals/trigger_cases.json",
    "references/command-routing.md",
    "references/evidence-contract.md",
    "references/investigation-workflows.md",
    "references/platform-invocation.md",
    "references/safety-and-claims.md",
    "scripts/run_next_action.py",
    "scripts/skill_doctor.py",
    "scripts/verify_bundle.py",
}
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
EVAL_MAX_BYTES = 64 * 1024


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


def validate_trigger_cases(skill_dir: pathlib.Path) -> tuple[int, int, int]:
    path = skill_dir / "evals/trigger_cases.json"
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SkillValidationError(f"cannot read trigger cases: {error}") from error
    if len(data) > EVAL_MAX_BYTES:
        raise SkillValidationError("trigger cases exceed the 64 KiB limit")
    try:
        value = json.loads(data.decode("utf-8"))
    # ValueError also owns UnicodeDecodeError, JSONDecodeError, and the
    # interpreter's integer string conversion limit raised by json.loads().
    except (ValueError, RecursionError) as error:
        raise SkillValidationError(f"cannot parse trigger cases: {error}") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SkillValidationError("trigger cases have an unsupported schema")
    if value.get("kind") != "auto_re_skill_trigger_cases":
        raise SkillValidationError("trigger cases have an unexpected kind")
    cases = value.get("cases")
    if not isinstance(cases, list):
        raise SkillValidationError("trigger cases must contain cases[]")
    command_routing = (skill_dir / "references/command-routing.md").read_text(
        encoding="utf-8"
    )
    seen: set[str] = set()
    positive = 0
    negative = 0
    narrow = 0
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise SkillValidationError(f"trigger cases[{index}] must be an object")
        case_id = case.get("id")
        prompt = case.get("prompt")
        should_trigger = case.get("should_trigger")
        route = case.get("expected_route")
        reason = case.get("reason")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise SkillValidationError(f"trigger cases[{index}].id is invalid")
        seen.add(case_id)
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 1000:
            raise SkillValidationError(f"trigger cases[{index}].prompt is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise SkillValidationError(f"trigger cases[{index}].reason is invalid")
        if not isinstance(should_trigger, bool):
            raise SkillValidationError(
                f"trigger cases[{index}].should_trigger must be boolean"
            )
        if should_trigger:
            positive += 1
            if not isinstance(route, str) or f"`{route}`" not in command_routing:
                raise SkillValidationError(
                    f"trigger cases[{index}].expected_route is not documented"
                )
            if route != "report":
                narrow += 1
        else:
            negative += 1
            if route is not None:
                raise SkillValidationError(
                    f"trigger cases[{index}] must not route a negative request"
                )
    if positive < 6 or negative < 5 or narrow < 4:
        raise SkillValidationError(
            "trigger corpus must retain at least 6 positive, 5 negative, and "
            "4 narrow-route cases"
        )
    return positive, negative, narrow


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
    if len(description) > 400 or "<" in description or ">" in description:
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
    if not re.search(
        r"^policy:\s*\n\s{2}allow_implicit_invocation:\s*true\s*$",
        openai_text,
        re.MULTILINE,
    ):
        raise SkillValidationError(
            "agents/openai.yaml must explicitly allow implicit invocation"
        )

    try:
        version = (skill_dir / "VERSION").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise SkillValidationError(f"cannot read Skill VERSION: {error}") from error
    if not VERSION_PATTERN.fullmatch(version):
        raise SkillValidationError("Skill VERSION must use x.y.z form")
    positive, negative, narrow = validate_trigger_cases(skill_dir)

    if len(content.splitlines()) > 500:
        raise SkillValidationError("SKILL.md exceeds the 500-line entrypoint limit")

    return {
        "ok": True,
        "name": name,
        "description_length": len(description),
        "implicit_invocation": True,
        "positive_trigger_count": positive,
        "negative_trigger_count": negative,
        "narrow_route_count": narrow,
        "version": version,
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
