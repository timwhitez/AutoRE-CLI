"""Root public instructions remain subject to distribution content checks."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("agent_docs_distribution", ROOT / "scripts/autore_distribution.py")
distribution = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = distribution
SPEC.loader.exec_module(distribution)


class AgentDocumentationTests(unittest.TestCase):
    def test_only_public_root_instructions_are_allowed(self):
        with tempfile.TemporaryDirectory(prefix="autore-agent-docs-") as temporary:
            root = Path(temporary)
            (root / "LICENSE-MIT").write_text("MIT\n")
            guide = root / "AGENTS.md"
            guide.write_text("# Public Distribution Instructions\n")
            distribution.validate_public_allowlist(root, [guide])
            for relative in ("nested/AGENTS.md", "CLAUDE.md"):
                path = root / relative
                path.parent.mkdir(exist_ok=True)
                path.write_text("# Instructions\n")
                with self.assertRaises(distribution.DistributionError):
                    distribution.validate_public_allowlist(root, [path])
            guide.write_text("# Auto-RE Core Instructions\n")
            with self.assertRaises(distribution.DistributionError):
                distribution.validate_public_allowlist(root, [guide])
            guide.write_text("# Public Distribution Instructions\npath=/private" + "/var/root/project\n")
            with self.assertRaises(distribution.DistributionError):
                distribution.validate_public_allowlist(root, [guide])
