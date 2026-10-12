"""Reject mismatched images, omitted audits and stale source evidence."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from verify_native_port import evidence_sources, validate_evidence


class EvidenceTests(unittest.TestCase):
    def test_stale_or_incomplete_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            original, generated, evidence = (work / n for n in ('original', 'generated', 'evidence.json'))
            original.write_bytes(b'original')
            generated.write_bytes(b'candidate')
            digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            report = dict(image_kind='mt1939-native-adapter', image_size=0x200000,
                          original_sha256=digest(original), output_sha256=digest(generated),
                          source_sha256={str(p.relative_to(ROOT)): digest(p) for p in evidence_sources()})
            audits = ('startup', 'adapter', 'error_and_cache_hooks', 'addressing_and_controls',
                      'transfer_modes', 'media', 'identification', 'bd_rom_di', 'read_timer',
                      'cd_transfer', 'packet_reparse', 'data_transfer', 'queued_commands',
                      'queued_nonreads', 'raw_state_and_recordable', 'zero_length', 'loader', 'programmer')
            report.update({name: {'unit_fixture': True} for name in audits})
            evidence.write_text(json.dumps(report))
            validate_evidence(evidence, original, generated)
            for field, value in (('output_sha256', 'wrong'), ('source_sha256', {}),
                                 ('programmer', {}), ('loader', None), ('zero_length', {})):
                changed = dict(report, **{field: value})
                evidence.write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    validate_evidence(evidence, original, generated)
            evidence.write_text(json.dumps(report))
            generated.write_bytes(b'changed candidate')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                validate_evidence(evidence, original, generated)
