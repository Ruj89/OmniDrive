"""Check C payload preservation and programming through the native NOR writer."""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
from map_scsi import require
from native_adapter import FLASH_PAYLOAD_BASE, FLASH_PAYLOAD_LIMIT, PROFILE_CHECKSUM_OFFSET
from validate_flash import checksum


def verify(original, candidate, inquiry, binary):
    from verify_loader import Utility
    from verify_programmer import run, PROGRAMMER_SHA256
    from hashlib import sha256
    require(original[FLASH_PAYLOAD_BASE:FLASH_PAYLOAD_LIMIT] ==
            b'\xff' * (FLASH_PAYLOAD_LIMIT - FLASH_PAYLOAD_BASE), 'C allocation overwrites profile data')
    require(candidate[0x1d0000:FLASH_PAYLOAD_BASE] == original[0x1d0000:FLASH_PAYLOAD_BASE] and
            candidate[FLASH_PAYLOAD_LIMIT:PROFILE_CHECKSUM_OFFSET] ==
            original[FLASH_PAYLOAD_LIMIT:PROFILE_CHECKSUM_OFFSET] and
            candidate[PROFILE_CHECKSUM_OFFSET + 4:] == original[PROFILE_CHECKSUM_OFFSET + 4:],
            'C payload changed existing profile data or reserved partitions')
    require(checksum(candidate, 0x1d0000, 0x1e0000)['delta'] == 0, 'C profile checksum mismatch')
    utility = Utility(binary)
    profile, report = utility.profile(inquiry)
    code = profile[6:6 + report['code_size']]
    require(sha256(code).hexdigest() == PROGRAMMER_SHA256, 'Unexpected flash programmer')
    cases = [run(code, original, candidate, jedec, 0x80) for jedec in (0xc22015, 0xc22415)]
    require(all(c['native_return_reached'] and c['final_array_matches_expected'] and
                c['native_readback_mismatches'] == 0 for c in cases), 'Native writer failed to retain C payload')
    return dict(cases=cases, existing_profile_bytes_preserved=True, profile_checksum_valid=True,
                c_payload_range=[FLASH_PAYLOAD_BASE, FLASH_PAYLOAD_LIMIT], hardware_tested=False)
