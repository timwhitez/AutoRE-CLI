"""Client-scoped registration checks; the CLI probe is a controlled test seam."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'registration_doctor', ROOT / 'skills/auto-re/scripts/skill_doctor.py')
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)


class SkillDoctorRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='autore-registration-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / 'home'
        self.project = self.root / 'project'
        self.project.mkdir()
        (self.project / '.git').mkdir()
        self.cli = self.root / 'trusted-cli'
        self.cli.write_text('controlled CLI probe fixture')

    def install(self, root, agent=None):
        root.mkdir(parents=True)
        (root / 'SKILL.md').write_text('---\nname: auto-re\n---\n')
        (root / 'VERSION').write_text('0.1.14\n')
        if agent is not None:
            files = ['SKILL.md', 'VERSION']
            (root / '.autore-managed.json').write_text(json.dumps({
                'schema_version': 1, 'kind': 'skill-install', 'skill': 'auto-re',
                'version': '0.1.14', 'agent': agent, 'managed_files': files,
                'sha256': doctor.installed_skill_digest(root, files),
            }))
        return root

    def diagnose(self, root, environment=None):
        with patch.object(Path, 'home', return_value=self.home), \
                patch.object(Path, 'cwd', return_value=self.project), \
                patch.object(doctor.os, 'environ', environment or {}), \
                patch.object(doctor.process_control, 'probe_output', return_value=b'auto-re-cli 0.1.14\n'):
            return doctor.diagnose(root, executable=self.cli)

    def test_default_dual_client_installations_are_independently_ready(self):
        trae = self.install(self.home / '.trae/skills/auto-re', 'trae')
        codex = self.install(self.home / '.agents/skills/auto-re', 'codex')
        for active, other in ((trae, codex), (codex, trae)):
            with self.subTest(active=active):
                result = self.diagnose(active)
                self.assertTrue(result['ok'], result)
                self.assertTrue(result['managed_content_match'])
                self.assertEqual(result['duplicate_count'], 0)
                self.assertNotIn(str(other), result['discovery_roots_checked'])

    def test_custom_managed_trae_path_uses_its_recorded_client(self):
        trae = self.install(self.root / 'custom-client/skills/auto-re', 'trae')
        self.install(self.home / '.agents/skills/auto-re', 'codex')
        result = self.diagnose(trae, {'TRAE_HOME': str(trae.parent.parent)})
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['duplicate_count'], 0)

    def test_same_client_project_registration_remains_a_duplicate(self):
        for agent, directory in (('trae', '.trae'), ('codex', '.agents')):
            with self.subTest(agent=agent):
                active = self.install(self.home / directory / 'skills/auto-re', agent)
                duplicate = self.install(self.project / directory / 'skills/auto-re')
                result = self.diagnose(active)
                self.assertFalse(result['ok'])
                self.assertEqual(result['duplicate_skill_roots'], [str(duplicate)])

    def test_unmanaged_conventional_trae_path_does_not_scan_codex(self):
        trae = self.install(self.home / '.trae/skills/auto-re')
        self.install(self.home / '.agents/skills/auto-re', 'codex')
        result = self.diagnose(trae)
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['skill']['managed'])
        self.assertEqual(result['duplicate_count'], 0)


if __name__ == '__main__':
    unittest.main()
