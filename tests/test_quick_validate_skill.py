"""Quick Skill checks reject broken copies without relying on distribution hashes."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "quick_validate_skill_tested", ROOT / "scripts/quick_validate_skill.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class QuickValidateSkillTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.skill = Path(self.temporary.name) / "skill"
        shutil.copytree(ROOT / "skills/auto-re", self.skill)

    def change_corpus(self, update):
        path = self.skill / "evals/trigger_cases.json"
        corpus = json.loads(path.read_text(encoding="utf-8"))
        update(corpus)
        path.write_text(json.dumps(corpus), encoding="utf-8")

    def test_complete_skill_passes(self):
        self.assertTrue(validator.validate_skill(self.skill)["ok"])

    def test_missing_first_evidence_launcher_is_named(self):
        (self.skill / "scripts/start_analysis.py").unlink()
        with self.assertRaisesRegex(validator.SkillValidationError, "start_analysis.py"):
            validator.validate_skill(self.skill)

    def test_interface_prompt_under_another_mapping_is_rejected(self):
        path = self.skill / "agents/openai.yaml"
        original = path.read_text(encoding="utf-8")
        lines = original.splitlines()
        prompt = next(line for line in lines if line.startswith("  default_prompt:"))
        lines.remove(prompt)
        for misplaced in (lines + [prompt], ["other:", prompt] + lines):
            with self.subTest(location=misplaced.index(prompt)):
                path.write_text("\n".join(misplaced) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(validator.SkillValidationError,
                                            r"interface\.default_prompt"):
                    validator.validate_skill(self.skill)

    def test_duplicate_interface_prompt_is_rejected(self):
        path = self.skill / "agents/openai.yaml"
        original = path.read_text(encoding="utf-8")
        prompt = next(line for line in original.splitlines()
                      if line.startswith("  default_prompt:"))
        path.write_text(original.replace(prompt, prompt + "\n" + prompt), encoding="utf-8")
        with self.assertRaisesRegex(validator.SkillValidationError, r"interface\.default_prompt"):
            validator.validate_skill(self.skill)

    def test_options_and_prose_literals_are_not_command_routes(self):
        routing = self.skill / "references/command-routing.md"
        with routing.open("a", encoding="utf-8") as handle:
            handle.write("\nUnrelated prose mentioning `not-a-command`.\n")
        for route in ("--addr", "not-a-command", "unknown-command"):
            with self.subTest(route=route):
                self.change_corpus(lambda corpus: next(
                    case for case in corpus["cases"] if case["id"] == "known_function"
                ).update(expected_route=route))
                with self.assertRaisesRegex(validator.SkillValidationError, "expected_route"):
                    validator.validate_skill(self.skill)

    def test_other_documented_commands_are_valid_routes(self):
        for route in ("dump-il", "archive", "replay", "batch-replay", "batch-diff"):
            with self.subTest(route=route):
                self.change_corpus(lambda corpus: next(
                    case for case in corpus["cases"] if case["id"] == "known_function"
                ).update(expected_route=route))
                self.assertTrue(validator.validate_skill(self.skill)["ok"])

    def test_schema_version_requires_integer_one(self):
        for version in (True, False, 1.0, "1", 0, 2, None):
            with self.subTest(version=version):
                self.change_corpus(lambda corpus: corpus.update(schema_version=version))
                with self.assertRaisesRegex(validator.SkillValidationError, "unsupported schema"):
                    validator.validate_skill(self.skill)
        self.change_corpus(lambda corpus: corpus.update(schema_version=1))
        self.assertTrue(validator.validate_skill(self.skill)["ok"])


if __name__ == "__main__":
    unittest.main()
