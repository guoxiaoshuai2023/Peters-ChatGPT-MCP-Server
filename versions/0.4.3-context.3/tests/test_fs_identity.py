import ctypes
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from peters_mcp.catalog import AccessError
from peters_mcp import fs_identity


class FilesystemIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='persistent-identity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.file = self.root / 'file'
        self.file.write_bytes(b'synthetic')

    def attribute(self, common, volume, payload):
        return struct.pack('=6I', 40, common, volume, 0, 0, 0) + payload

    def test_real_fd_file_directory_and_boot_uuid(self):
        for path in (self.root, self.file):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                identity = fs_identity.persistent_identity_fd(fd)
                self.assertEqual(identity, fs_identity.persistent_identity(path))
                self.assertEqual(identity['file_id'], os.fstat(fd).st_ino)
                self.assertEqual(fs_identity.validate_identity(identity), identity)
                self.assertEqual(os.fstat(fd).st_ino, path.stat().st_ino)
            finally:
                os.close(fd)
        first = fs_identity.boot_session_id()
        self.assertEqual(len(first), 36)
        self.assertEqual(first, fs_identity.boot_session_id())

    def test_wire_shape_rejects_boolean_numbers_extra_keys_and_noncanonical_uuid(self):
        original = fs_identity.persistent_identity(self.root)
        for field, value in [('format', True), ('format', 1), ('file_id', True), ('file_id', -1),
                             ('file_id', 2 ** 64), ('birthtime_ns', 0), ('birthtime_ns', 1.5),
                             ('platform', 'linux'), ('volume_uuid', '0' * 32),
                             ('volume_uuid', original['volume_uuid'].upper())]:
            with self.subTest(field=field, value=value), self.assertRaises(AccessError):
                fs_identity.validate_identity(dict(original, **{field: value}))
        for value in (None, [], dict(original, st_dev=42), {k: v for k, v in original.items() if k != 'format'}):
            with self.subTest(value=value), self.assertRaises(AccessError):
                fs_identity.validate_identity(value)

    def test_symlink_at_file_or_intermediate_component_and_relative_path_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.file)
        directory_alias = self.root / 'directory-alias'
        directory_alias.symlink_to(self.root, target_is_directory=True)
        for path in (alias, directory_alias / 'file', Path('relative')):
            with self.subTest(path=path), self.assertRaises(AccessError):
                fs_identity.persistent_identity(path)

    def test_exact_40_byte_layout_requires_returned_attributes_but_not_vol_info(self):
        volume = bytes.fromhex('1234567890abcdef1234567890abcdef')
        birth = struct.pack('=qq', 1700000000, 123456789)
        calls = []
        def attributes(fd, common, vol):
            calls.append((common, vol))
            if vol:
                return self.attribute(fs_identity._RETURNED, fs_identity._VOL_UUID, volume)
            return self.attribute(fs_identity._RETURNED | fs_identity._CRTIME, 0, birth)
        with patch.object(fs_identity, '_attribute_bytes', attributes):
            value = fs_identity.persistent_identity(self.file)
        self.assertEqual(value['birthtime_ns'], 1700000000123456789)
        self.assertEqual(value['volume_uuid'], '12345678-90ab-cdef-1234-567890abcdef')
        self.assertEqual(calls, [(fs_identity._RETURNED, fs_identity._VOL_INFO | fs_identity._VOL_UUID),
                                 (fs_identity._RETURNED | fs_identity._CRTIME, 0)])

    def test_zero_uuid_truncation_wrong_length_or_missing_mask_fails_closed(self):
        valid = self.attribute(fs_identity._RETURNED, fs_identity._VOL_UUID,
                               bytes.fromhex('1234567890abcdef1234567890abcdef'))
        invalid = [valid[:-1], bytes(40), struct.pack('=I', 41) + valid[4:],
                   self.attribute(fs_identity._RETURNED, 0, valid[24:]),
                   self.attribute(fs_identity._RETURNED, fs_identity._VOL_UUID, bytes(16)),
                   self.attribute(fs_identity._RETURNED, fs_identity._VOL_UUID | fs_identity._VOL_INFO,
                                  valid[24:])]
        for raw in invalid:
            with self.subTest(raw=raw), patch.object(fs_identity, '_attribute_bytes', return_value=raw):
                with self.assertRaises(AccessError):
                    fs_identity.persistent_identity(self.file)

    def test_negative_seconds_and_out_of_range_nanoseconds_fails_closed(self):
        for seconds, nanos in [(-1, 0), (1, -1), (1, 10 ** 9), (0, 0)]:
            def attributes(fd, common, volume):
                if volume:
                    return self.attribute(fs_identity._RETURNED, fs_identity._VOL_UUID, b'1' * 16)
                return self.attribute(fs_identity._RETURNED | fs_identity._CRTIME, 0,
                                      struct.pack('=qq', seconds, nanos))
            with self.subTest(seconds=seconds, nanos=nanos), patch.object(fs_identity, '_attribute_bytes', attributes):
                with self.assertRaises(AccessError):
                    fs_identity.persistent_identity(self.file)

    def test_native_error_and_unsupported_platform_have_no_fallback(self):
        with patch.object(fs_identity, '_library', side_effect=OSError('synthetic FFI failure')):
            with self.assertRaisesRegex(AccessError, 'identity_unsupported'):
                fs_identity.persistent_identity(self.file)
            with self.assertRaisesRegex(AccessError, 'identity_unsupported'):
                fs_identity.boot_session_id()
        with patch.object(fs_identity.sys, 'platform', 'unsupported'):
            with self.assertRaisesRegex(AccessError, 'identity_unsupported'):
                fs_identity.persistent_identity(self.file)

    def test_path_replacement_and_permission_change_during_fd_query_refused(self):
        original = fs_identity._attribute_bytes
        for mutation in ('replace', 'chmod'):
            fired = False
            def attributes(fd, common, volume):
                nonlocal fired
                output = original(fd, common, volume)
                if not fired:
                    fired = True
                    if mutation == 'replace':
                        self.file.rename(self.root / 'original')
                        self.file.write_text('replacement')
                    else:
                        self.file.chmod(0o400)
                return output
            with self.subTest(mutation=mutation), patch.object(fs_identity, '_attribute_bytes', attributes):
                with self.assertRaisesRegex(AccessError, 'identity_mismatch'):
                    fs_identity.persistent_identity(self.file)
            self.file.chmod(0o600)

    def test_directory_child_mkdir_and_rmdir_preserve_held_fd_identity(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            identity = fs_identity.persistent_identity_fd(fd)
            original = fs_identity._attribute_bytes
            child = self.root / 'ordinary-child-directory'
            for operation in (child.mkdir, child.rmdir):
                before = os.fstat(fd)
                changed = []
                def attributes(current, common, volume):
                    output = original(current, common, volume)
                    if not changed:
                        self.assertEqual(current, fd)
                        operation()
                        changed.append(os.fstat(fd))
                    return output
                with self.subTest(operation=operation.__name__), patch.object(fs_identity, '_attribute_bytes', attributes):
                    self.assertEqual(fs_identity.persistent_identity_fd(fd), identity)
                self.assertEqual(len(changed), 1)
                self.assertNotEqual(before.st_nlink, changed[0].st_nlink)
                self.assertEqual((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid),
                                 (changed[0].st_dev, changed[0].st_ino, changed[0].st_mode,
                                  changed[0].st_uid, changed[0].st_gid))
                self.assertEqual(fs_identity.persistent_identity_fd(fd), identity)
        finally:
            os.close(fd)

    def test_regular_file_hardlink_change_during_fd_query_remains_rejected(self):
        original = fs_identity._attribute_bytes
        changed = []
        def attributes(fd, common, volume):
            output = original(fd, common, volume)
            if not changed:
                before = os.fstat(fd)
                os.link(self.file, self.root / 'hardlink')
                changed.append((before.st_nlink, os.fstat(fd).st_nlink))
            return output
        with patch.object(fs_identity, '_attribute_bytes', attributes):
            with self.assertRaisesRegex(AccessError, 'identity_mismatch'):
                fs_identity.persistent_identity(self.file)
        self.assertEqual(changed, [(1, 2)])

    def test_directory_replacement_or_mode_change_during_fd_query_still_rejected(self):
        original = fs_identity._attribute_bytes
        for mutation in ('replace', 'chmod'):
            directory = self.root / mutation
            directory.mkdir(mode=0o700)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            changed = []
            def attributes(current, common, volume):
                output = original(current, common, volume)
                if not changed:
                    if mutation == 'replace':
                        directory.rename(self.root / 'retired-directory')
                        directory.mkdir(mode=0o700)
                    else:
                        directory.chmod(0o500)
                    changed.append(True)
                return output
            try:
                with self.subTest(mutation=mutation), patch.object(fs_identity, '_attribute_bytes', attributes):
                    with self.assertRaisesRegex(AccessError, 'identity_mismatch'):
                        fs_identity.persistent_identity_fd(fd)
            finally:
                os.close(fd)

    def test_close_uncertainty_propagates_without_retrying_same_fd(self):
        original = os.close
        seen = []
        def close(fd):
            seen.append(fd)
            original(fd)
            if len(seen) == 1:
                raise OSError('synthetic close uncertainty after actual close')
        with patch.object(fs_identity.os, 'close', close):
            with self.assertRaisesRegex(AccessError, 'identity_cleanup_pending'):
                fs_identity.persistent_identity(self.file)
        self.assertEqual(len(seen), len(set(seen)))

    def test_boot_uuid_rejects_native_error_or_malformed_return(self):
        class Function:
            def __init__(self, raw, result=0):
                self.raw, self.result = raw, result
            def __call__(self, name, output, length, new_value, new_length):
                self.name = name
                ctypes.memmove(output, self.raw, len(self.raw))
                ctypes.cast(length, ctypes.POINTER(ctypes.c_size_t)).contents.value = len(self.raw)
                return self.result
        class Library:
            pass
        for raw, result in [(b'invalid\0', 0), (b'00000000-0000-0000-0000-000000000000\0', 0),
                            (b'12345678-90ab-cdef-1234-567890abcdef', 0), (b'\0', -1)]:
            library = Library()
            library.sysctlbyname = Function(raw, result)
            with self.subTest(raw=raw, result=result), patch.object(fs_identity, '_library', return_value=library):
                with self.assertRaisesRegex(AccessError, 'identity_unsupported'):
                    fs_identity.boot_session_id()
            self.assertEqual(library.sysctlbyname.name, b'kern.bootsessionuuid')


if __name__ == '__main__':
    unittest.main()
