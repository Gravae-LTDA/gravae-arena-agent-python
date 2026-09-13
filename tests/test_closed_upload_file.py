import os
import tempfile
import unittest
from pathlib import Path
from direct_upload_queue import open_writer_inodes

class ClosedFileTests(unittest.TestCase):
    def test_writable_descriptor_blocks_but_readonly_does_not(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'123/fd').mkdir(parents=True)
            (root/'123/fdinfo').mkdir()
            source = root/'clip.mp4'
            source.write_bytes(b'video')
            (root/'123/fd/7').symlink_to(source)
            info = root/'123/fdinfo/7'
            info.write_text('flags:\t0100001\n')
            st = source.stat()
            self.assertIn((st.st_dev, st.st_ino), open_writer_inodes(root))
            info.write_text('flags:\t0100000\n')
            self.assertNotIn((st.st_dev, st.st_ino), open_writer_inodes(root))

    @unittest.skipUnless(Path('/proc/self/fd').exists(), 'Linux procfs required')
    def test_real_open_writer_then_closed_file(self):
        # Exercise real Linux descriptors without requiring visibility into other users.
        with tempfile.TemporaryDirectory() as proc:
            (Path(proc)/str(os.getpid())).symlink_to(Path('/proc')/str(os.getpid()))
            with tempfile.NamedTemporaryFile() as source:
                st = os.fstat(source.fileno())
                self.assertIn((st.st_dev, st.st_ino), open_writer_inodes(proc))
            self.assertNotIn((st.st_dev, st.st_ino), open_writer_inodes(proc))
