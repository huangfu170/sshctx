import io
import json
import pathlib
import tempfile
import unittest

import agent


class AgentTests(unittest.TestCase):
    def test_frame_round_trip_includes_binary(self):
        stream = io.BytesIO()
        agent.write_frame(stream, {"id": "1"}, b"\x00\xff")
        stream.seek(0)
        self.assertEqual(agent.read_frame(stream), ({"id": "1"}, b"\x00\xff"))

    def test_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            service = agent.Agent([root])
            with self.assertRaises(PermissionError):
                service.path(outside)

    def test_atomic_write_and_read(self):
        with tempfile.TemporaryDirectory() as root:
            service = agent.Agent([root])
            target = pathlib.Path(root) / "x.bin"
            result, _ = service.op_write_atomic({"path": str(target)}, b"abc")
            self.assertEqual(result["bytes"], 3)
            metadata, payload = service.op_read({"path": str(target)}, b"")
            self.assertEqual(payload, b"abc")
            self.assertIsNone(metadata["next_byte_offset"])

    def test_chunk_resume_and_commit(self):
        with tempfile.TemporaryDirectory() as root:
            service = agent.Agent([root])
            target = pathlib.Path(root) / "nested" / "large.bin"
            service.op_write_chunk({"path": str(target), "offset": 0, "reset": True}, b"abc")
            status, _ = service.op_chunk_status({"path": str(target)}, b"")
            self.assertEqual(status["offset"], 3)
            service.op_write_chunk({"path": str(target), "offset": 3}, b"def")
            digest = agent.hashlib.sha256(b"abcdef").hexdigest()
            service.op_commit_chunks({"path": str(target), "sha256": digest}, b"")
            self.assertEqual(target.read_bytes(), b"abcdef")


if __name__ == "__main__":
    unittest.main()
