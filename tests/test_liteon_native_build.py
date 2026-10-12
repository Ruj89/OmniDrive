"""Verify the actual armips -> update_cmac production command sequence."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from audit_integrity import CHECKSUM_OFFSET, output_name
from finalize_native import finalize_if_native
from native_adapter import assemble, build_libraries, C_FLAGS, LIBRARIES, PROFILE_CHECKSUM_OFFSET


class NativeBuildTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips required')
        self.original = path.read_bytes()

    def test_production_sequence_matches_verified_build(self):
        expected, _ = assemble(self.original)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            shutil.copytree(ROOT / 'asm', work / 'asm')
            for name in ('build', 'firmware', 'patched_firmware'):
                (work / name).mkdir()
            build_libraries(work / 'build')
            (work / 'firmware/ASUS_BW-12B1LT_1.03.bin').write_bytes(self.original)
            subprocess.run(['armips', 'ASUS_BW-12B1LT_1.03.asm'], cwd=work / 'asm',
                           capture_output=True, check=True)
            result = work / 'patched_firmware' / output_name()
            raw = result.read_bytes()
            subprocess.run([sys.executable, str(ROOT / 'scripts/update_cmac.py'), str(result)],
                           capture_output=True, check=True)
            self.assertEqual(result.read_bytes(), expected)
            # armips leaves both sums at their original values; only they differ.
            self.assertEqual(raw[:CHECKSUM_OFFSET], expected[:CHECKSUM_OFFSET])
            self.assertEqual(raw[CHECKSUM_OFFSET + 4:PROFILE_CHECKSUM_OFFSET],
                             expected[CHECKSUM_OFFSET + 4:PROFILE_CHECKSUM_OFFSET])
            self.assertEqual(raw[PROFILE_CHECKSUM_OFFSET + 4:], expected[PROFILE_CHECKSUM_OFFSET + 4:])
            self.assertTrue(finalize_if_native(result))
            self.assertEqual(result.read_bytes(), expected)

    def test_other_images_are_left_to_the_cmac_path(self):
        with tempfile.TemporaryDirectory() as directory:
            for image in (bytes(0x200000), self.original[:-1]):
                target = Path(directory) / 'arbitrary-name.bin'
                target.write_bytes(image)
                self.assertFalse(finalize_if_native(target))
                self.assertEqual(target.read_bytes(), image)

    def test_cmake_flags_match_isolated_build(self):
        flags = {'libOmniDrive.a': ROOT / 'build/CMakeFiles/OmniDrive.dir/flags.make',
                 'libOmniDriveMT1939.a': ROOT / 'build/CMakeFiles/OmniDriveMT1939.dir/flags.make'}
        if not all(path.exists() for path in flags.values()):
            self.skipTest('Configured CMake build directory required')
        for library, path in flags.items():
            match = re.search(r'^C_FLAGS = (.*)$', path.read_text(), re.M)
            self.assertEqual(sorted(match.group(1).split()),
                             sorted(C_FLAGS + LIBRARIES[library][1]), library)

    def test_cmake_regenerates_image_when_patch_inputs_change(self):
        if shutil.which('cmake') is None:
            self.skipTest('CMake required')
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name in ('asm', 'src', 'cmake'):
                shutil.copytree(ROOT / name, work / name)
            for name in ('CMakeLists.txt', 'arm-toolchain.cmake'):
                shutil.copy2(ROOT / name, work / name)
            for name in ('firmware', 'patched_firmware', 'scripts', 'tools/liteon/patch_build'):
                (work / name).mkdir(parents=True)
            for name in ('scripts/update_cmac.py', 'tools/liteon/patch_build/finalize_native.py'):
                shutil.copy2(ROOT / name, work / name)
            original = work / 'firmware/ASUS_BW-12B1LT_1.03.bin'
            original.write_bytes(self.original)
            subprocess.run(['cmake', '-S', str(work), '-B', str(work / 'build')],
                           capture_output=True, check=True)

            def build():
                return subprocess.run(['cmake', '--build', str(work / 'build'),
                                       '--target', 'ASUS_BW_12B1LT_1_03'],
                                      capture_output=True, text=True, check=True).stdout

            build()
            output = work / 'patched_firmware' / output_name()
            self.assertEqual(output.read_bytes(), assemble(self.original)[0])
            self.assertNotIn('Patching firmware', build())

            hooks = work / 'asm/liteon/mt1939.asm'
            hooks.write_text(hooks.read_text().replace('.ascii "OmniDrive"', '.ascii "OmniDrivX"'))
            self.assertIn('Patching firmware', build())
            self.assertEqual(output.read_bytes()[0x1c6f82:0x1c6f8b], b'OmniDrivX')

            profile = work / 'asm/ASUS_BW-12B1LT_1.03.asm'
            profile.write_text(profile.read_text().replace('InquiryDataPatch,0x1C6F82',
                                                           'InquiryDataPatch,0x1C6F83'))
            self.assertIn('Patching firmware', build())
            self.assertEqual(output.read_bytes()[0x1c6f83:0x1c6f8c], b'OmniDrivX')

            version = work / 'asm/version.asm'
            version.write_text(version.read_text() + '\n; dependency check\n')
            self.assertIn('Patching firmware', build())

            changed = bytearray(self.original)
            changed[0x1000] ^= 1
            original.write_bytes(changed)
            self.assertIn('Patching firmware', build())
            self.assertEqual(output.read_bytes()[0x1000], changed[0x1000])

            for name in ('scripts/update_cmac.py', 'tools/liteon/patch_build/finalize_native.py'):
                source = work / name
                source.write_text("print('checksum dependency check')\n" + source.read_text())
                self.assertIn('checksum dependency check', build())
            self.assertNotIn('Patching firmware', build())

    def test_native_writer_keeps_c_payload_and_existing_profile_data(self):
        import json
        utility = Path('/tmp/omnidrive-Flash_Utility.exe')
        capture = ROOT / 'dump/report.json'
        if not utility.exists() or not capture.exists():
            self.skipTest('Pinned utility and original INQUIRY capture required')
        from verify_native_programmer import verify
        candidate, _ = assemble(self.original)
        result = verify(self.original, candidate, bytes.fromhex(
            json.loads(capture.read_text())['extended_inquiry_hex']), utility.read_bytes())
        self.assertEqual(len(result['cases']), 2)
        self.assertTrue(result['existing_profile_bytes_preserved'])
        self.assertTrue(result['profile_checksum_valid'])


if __name__ == '__main__':
    unittest.main()
