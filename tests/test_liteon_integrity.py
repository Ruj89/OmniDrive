import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools/liteon"
for name in ("read_flash", "decode_flash", "validate_flash", "audit_integrity", "trace_integrity"):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
audit = sys.modules["audit_integrity"]
patch = audit


class IntegrityComparisonTests(unittest.TestCase):
    def test_rejects_truncated_readback(self):
        with self.assertRaises(audit.ReadError):
            audit.compare_readback(bytes(0x200000), bytes(0x1fffff))

    def test_identical_and_each_region_corruption(self):
        original = bytes(0x200000)
        self.assertTrue(audit.compare_readback(original, original)["byte_identical_to_original"])
        for name, start, end in audit.REGIONS:
            damaged = bytearray(original)
            damaged[end - 1] = 1
            report = audit.compare_readback(original, damaged)
            self.assertFalse(report["byte_identical_to_original"])
            self.assertEqual(report["changed_byte_count"], 1)
            self.assertEqual({n for n, equal in report["regions_identical"].items() if not equal}, {name})


class LocalIntegritySpecimenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "firmware/ASUS_BW-12B1LT_1.03.bin"
        if not path.exists():
            raise unittest.SkipTest("Local research specimen is not distributed")
        cls.original = path.read_bytes()
        cls.experimental, _ = patch.build(cls.original)

    def test_original_audit_and_patch_not_rollback(self):
        report = audit.audit(ROOT / "dump", self.original, self.experimental)
        self.assertTrue(report["offline_integrity_consistent"])
        self.assertTrue(report["integrity_header_unchanged"])
        self.assertEqual(report["experimental_checksums"]["main"]["delta"], 0x80)
        self.assertFalse(report["flash_ready"])
        self.assertFalse(report["restore_readback_verified"])
        rollback = audit.compare_readback(self.original, self.experimental)
        self.assertFalse(rollback["byte_identical_to_original"])
        self.assertEqual(rollback["changed_byte_count"], 2)

    def test_rejects_damaged_patch_and_baseline(self):
        damaged = bytearray(self.experimental)
        damaged[0x1d0040] ^= 1
        with self.assertRaises(audit.ReadError):
            audit.audit(ROOT / "dump", self.original, damaged)
        with self.assertRaises(audit.ReadError):
            audit.audit(ROOT / "dump", self.experimental, self.experimental)

    def test_requires_both_readback_inputs(self):
        with self.assertRaises(audit.ReadError):
            audit.audit(ROOT / "dump", self.original, self.experimental, ROOT / "dump")

    def test_identical_supplied_readback_does_not_certify_hardware_trial(self):
        # This is the original backup supplied twice, NOT a hardware restore.
        report = audit.audit(ROOT / "dump", self.original, self.experimental,
                             ROOT / "dump", ROOT / "firmware/ASUS_BW-12B1LT_1.03.bin")
        self.assertTrue(report["restore_readback_verified"])
        self.assertFalse(report["flash_ready"])

    def test_native_header_selector_trace(self):
        try:
            import unicorn
        except ImportError:
            self.skipTest("Unicorn research dependency is not installed")
        report = sys.modules["trace_integrity"].trace(self.original)
        self.assertEqual(len(report["runs"]), 12)
        self.assertTrue(report["observed_startup_call_checks_no_tags"])
        self.assertFalse(report["flash_ready"])


if __name__ == "__main__":
    unittest.main()
