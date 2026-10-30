"""Behavior and evidence invariants, using only synthetic data."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import subprocess
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "skills/cloneguard/scripts/cloneguard.py"
spec = importlib.util.spec_from_file_location("cloneguard", SCRIPT)
cg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cg
spec.loader.exec_module(cg)


def zipped(entries, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return out.getvalue()


class CloneGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "app"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def rules(self, report):
        return {item["rule"] for item in report["findings"]}

    def test_secret_report_never_contains_raw_credential(self):
        secret = "ghp_" + "Ab9" * 13
        self.put("bundle.js", f'export const token = "{secret}";')
        report = cg.Auditor().run(self.root)
        self.assertIn("github-token", self.rules(report))
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(cg.audit_exit(report, "high"), 1)

    def test_renamed_sourcemap_still_detected(self):
        self.put("data.json", json.dumps({"version": 3, "sourcesContent": ["privateSource()"]}))
        self.assertIn("embedded-source-content", self.rules(cg.Auditor().run(self.root)))

    def test_inline_source_map_fails_gate(self):
        self.put("app.js", "//# sourceMappingURL=data:application/json;base64,e30=")
        self.assertEqual(cg.audit_exit(cg.Auditor().run(self.root), "high"), 1)

    def test_stack_detection_supports_mixed_projects(self):
        self.put("mac/Package.swift", "// swift-tools-version: 6.0")
        self.put("android/build.gradle.kts", "plugins {}")
        self.put("api/go.mod", "module example.invalid/test")
        self.put("native/Cargo.toml", "[package]")
        self.put("desktop/app.csproj", "<Project />")
        self.put("web/package.json", '{"dependencies":{"electron":"1","react-native":"1"}}')
        report = cg.Auditor(scope="source").run(self.root)
        self.assertTrue({"apple-swift", "android-jvm", "go-native", "rust-native", "dotnet", "electron", "react-native"} <= set(report["stacks"]))

    def test_source_exclusions_are_visible_release_has_no_silent_exclusions(self):
        self.put("node_modules/example/index.js", "nothing")
        source = cg.Auditor(scope="source").run(self.root)
        release = cg.Auditor().run(self.root)
        self.assertIn("node_modules", source["excluded_by_source_policy"])
        self.assertEqual(release["files_screened"], 1)

    def test_byte_budget_is_incomplete_even_with_fail_on_none(self):
        self.put("big.js", "x" * 100)
        report = cg.Auditor(cg.Limits(file_bytes=10)).run(self.root)
        self.assertFalse(report["complete"])
        self.assertEqual(cg.audit_exit(report, "none"), 2)

    def test_empty_audit_is_not_a_pass(self):
        report = cg.Auditor().run(self.root)
        self.assertEqual(cg.audit_exit(report, "high"), 2)

    def test_unreadable_native_container_is_unassessed(self):
        self.put("app.asar", "opaque")
        report = cg.Auditor().run(self.root)
        self.assertFalse(report["complete"])

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlinks")
    def test_symlink_never_followed_or_staged(self):
        secret = self.base / "private.txt"
        secret.write_text("outside")
        try:
            (self.root / "link").symlink_to(secret)
        except OSError:
            self.skipTest("symlink privilege unavailable")
        report = cg.Auditor().run(self.root)
        self.assertFalse(report["complete"])
        self.assertEqual(report["files_screened"], 0)
        with self.assertRaises(cg.GuardError):
            cg.stage(self.root, self.base / "public")
        self.assertEqual(secret.read_text(), "outside")

    def test_nested_archive_screens_members_without_extracting(self):
        self.put("app.ipa", zipped([("inner.zip", zipped([(".env", b"PASSWORD=example")]))]))
        report = cg.Auditor().run(self.root)
        self.assertIn("environment-file", self.rules(report))
        self.assertFalse((self.root / ".env").exists())

    def test_archive_expansion_budget_is_not_clean(self):
        self.put("bomb.zip", zipped([("huge.txt", b"a" * 100000)], zipfile.ZIP_DEFLATED))
        report = cg.Auditor().run(self.root)
        self.assertFalse(report["complete"])
        self.assertIn("archive-expansion-budget", {x["reason"] for x in report["skipped"]})

    def test_archive_traversal_and_duplicate_members_are_flagged(self):
        self.put("bad.zip", zipped([("../escape", b"x"), ("same", b"1"), ("same", b"2")]))
        report = cg.Auditor().run(self.root)
        self.assertIn("archive-path", self.rules(report))
        self.assertFalse(report["complete"])
        self.assertFalse((self.base / "escape").exists())

    def test_archive_depth_is_bounded(self):
        self.put("nested.zip", zipped([("nested.zip", zipped([("nested.zip", zipped([("a", b"x")]))]))]))
        report = cg.Auditor().run(self.root)
        self.assertIn("archive-depth-budget", {x["reason"] for x in report["skipped"]})

    def test_plist_roundtrip_and_debug_entitlement(self):
        valid = plistlib.dumps({"get-task-allow": True}, fmt=plistlib.FMT_BINARY)
        self.put("entitlements.plist", valid)
        report = cg.Auditor().run(self.root)
        self.assertIn("apple-debug-entitlement", self.rules(report))
        self.assertTrue(report["complete"])
        self.put("entitlements.plist", valid + b"\0unrecognized-trailer\0")
        self.assertFalse(cg.Auditor().run(self.root)["complete"])

    def test_magic_detection_does_not_trust_extension(self):
        self.put("renamed.txt", b"\x00asm\x01\x00\x00\x00")
        self.assertEqual(cg.Auditor().run(self.root)["inventory"][0]["format"], "wasm")

    def test_stage_preserves_bytes_mode_and_originals(self):
        script = self.put("app.js", "export const answer = 42;")
        script.chmod(0o755)
        source_map = self.put("app.js.map", '{"version":3,"sourcesContent":["original"]}')
        self.put(".env", "private=yes")
        self.put(".git/config", "private-repository")
        original_hash = cg.hash_regular(script)
        output = self.base / "public"
        result = cg.stage(self.root, output)
        self.assertEqual(cg.hash_regular(output / "app.js"), original_hash)
        self.assertTrue(source_map.exists())
        self.assertFalse((output / "app.js.map").exists())
        self.assertFalse((output / ".env").exists())
        self.assertFalse((output / ".git").exists())
        self.assertEqual(result["retained_files"], 1)

    def test_stage_dry_run_does_not_write(self):
        self.put("index.html", "<h1>example</h1>")
        output = self.base / "public"
        cg.stage(self.root, output, dry_run=True)
        self.assertFalse(output.exists())

    def test_stage_rejects_overwrite_and_nested_outputs(self):
        self.put("index.html", "example")
        for output in [self.root, self.root / "nested", self.base]:
            with self.assertRaises(cg.GuardError):
                cg.stage(self.root, output)

    def test_stage_rejects_native_and_signed_bundles(self):
        for name, data in [("Example.app/Info.plist", b"example"), ("a.exe", b"MZexample"), ("script.py", b"print(1)")]:
            path = self.put(name, data)
            with self.assertRaises(cg.GuardError):
                cg.stage(self.root, self.base / "public")
            path.unlink()
        self.assertFalse((self.base / "public").exists())

    def test_stage_unresolved_secret_leaves_no_output(self):
        self.put("bundle.js", 'const key="sk_live_' + "A" * 32 + '";')
        output = self.base / "public"
        with self.assertRaises(cg.GuardError):
            cg.stage(self.root, output)
        self.assertFalse(output.exists())

    def test_manifest_detects_changes_missing_added_and_mode(self):
        self.put("app.bin", b"\x00arbitrary")
        self.put("b.txt", "second")
        manifest = self.base / "release.json"
        cg.manifest(self.root, manifest)
        self.assertTrue(cg.verify(self.root, manifest)["matches"])
        self.put("app.bin", b"modified")
        (self.root / "b.txt").unlink()
        self.put("added.txt", "unexpected")
        report = cg.verify(self.root, manifest)
        self.assertEqual(report["changed"], ["app.bin"])
        self.assertEqual(report["missing"], ["b.txt"])
        self.assertEqual(report["added"], ["added.txt"])

    def test_authenticated_manifest_rejects_wrong_key_tamper_and_downgrade(self):
        self.put("app", "payload")
        key = self.base / "key"
        wrong = self.base / "wrong-key"
        key.write_bytes(b"a" * 32)
        wrong.write_bytes(b"b" * 32)
        manifest = self.base / "release.json"
        cg.manifest(self.root, manifest, key)
        self.assertTrue(cg.verify(self.root, manifest, key)["authenticated"])
        for candidate in (None, wrong):
            with self.assertRaises(cg.GuardError):
                cg.verify(self.root, manifest, candidate)
        body = json.loads(manifest.read_text())
        body["entries"][0]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(body))
        with self.assertRaises(cg.GuardError):
            cg.verify(self.root, manifest, key)
        body.pop("authentication")
        manifest.write_text(json.dumps(body))
        with self.assertRaises(cg.GuardError):
            cg.verify(self.root, manifest, key)

    def test_manifest_inside_release_and_key_inside_release_rejected(self):
        self.put("app", "payload")
        with self.assertRaises(cg.GuardError):
            cg.manifest(self.root, self.root / "manifest.json")
        key = self.put("key", b"x" * 32)
        with self.assertRaises(cg.GuardError):
            cg.manifest(self.root, self.base / "manifest.json", key)

    def test_malicious_manifest_paths_rejected(self):
        self.put("app", "payload")
        path = self.base / "manifest.json"
        cg.manifest(self.root, path)
        body = json.loads(path.read_text())
        for bad in ["../outside", "/tmp/outside", "C:/outside", "a\\outside", "a//outside"]:
            body["entries"][0]["path"] = bad
            path.write_text(json.dumps(body))
            with self.assertRaises(cg.GuardError):
                cg.verify(self.root, path)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(cg.GuardError):
            cg.load_json(b'{"entries":[],"entries":[]}')

    def test_canaries_are_deterministic_scoped_and_not_credentials(self):
        key = self.base / "key"
        key.write_bytes(b"a" * 32)
        paths = [self.base / f"marker{i}.json" for i in range(3)]
        cg.canary("app", "build1", key, paths[0])
        cg.canary("app", "build1", key, paths[1])
        cg.canary("app", "build2", key, paths[2])
        markers = [json.loads(p.read_text()) for p in paths]
        self.assertEqual(markers[0]["token"], markers[1]["token"])
        self.assertNotEqual(markers[0]["token"], markers[2]["token"])
        self.put("resource.json", paths[0].read_bytes())
        report = cg.Auditor(needle=markers[0]["token"].encode()).run(self.root)
        self.assertEqual(report["canary_matches"], ["resource.json"])
        self.assertNotIn("github-token", self.rules(report))

    def test_output_files_are_exclusive_and_key_permissions_private(self):
        key = self.base / "key"
        cg.create_file(key, b"x" * 32, private=True)
        with self.assertRaises(FileExistsError):
            cg.create_file(key, b"replacement")
        self.assertEqual(key.read_bytes(), b"x" * 32)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)

    def test_cli_exit_status_and_json(self):
        self.put("test.map", "{}")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cg.main(["audit", str(self.root)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["schema"], "cloneguard.audit.v1")

    def test_mcp_stdio_handshake_and_real_audit(self):
        self.put("index.html", "<main>hello</main>")
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cloneguard_audit", "arguments": {"path": "."}}},
        ]
        process = subprocess.run([sys.executable, str(SCRIPT), "mcp", "--root", str(self.root)],
                                 input="\n".join(json.dumps(x) for x in messages) + "\n", text=True, capture_output=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(len(responses[1]["result"]["tools"]), 2)
        report = json.loads(responses[2]["result"]["content"][0]["text"])
        self.assertEqual(report["files_screened"], 1)

    def test_mcp_rejects_path_escape_and_extra_arguments(self):
        outside = self.base / "outside.js"
        outside.write_text("private")
        for arguments in ({"path": "../outside.js"}, {"path": str(outside)}, {"path": ".", "command": "arbitrary"}):
            with self.assertRaises(cg.GuardError):
                cg.mcp_call(self.root, "cloneguard_audit", arguments)

    def test_mcp_malformed_input_does_not_corrupt_next_response(self):
        incoming = io.BytesIO(b'not-json\n{"jsonrpc":"2.0","id":4,"method":"ping"}\n')
        outgoing = io.StringIO()
        cg.serve_mcp(self.root, incoming, outgoing)
        replies = [json.loads(line) for line in outgoing.getvalue().splitlines()]
        self.assertEqual(replies[0]["error"]["code"], -32700)
        self.assertEqual(replies[1]["result"], {})

    def test_report_cannot_be_written_into_public_release(self):
        self.put("index.html", "example")
        output, errors = io.StringIO(), io.StringIO()
        report_path = self.root / "private-findings.json"
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = cg.main(["audit", str(self.root), "--out", str(report_path)])
        self.assertEqual(code, 2)
        self.assertFalse(report_path.exists())

    def test_corrupted_compressed_zip_is_incomplete(self):
        data = bytearray(zipped([("data.txt", b"hello world" * 100)], zipfile.ZIP_DEFLATED))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.infolist()[0]
            data_start = info.header_offset + 30 + len(info.filename.encode())
        data[data_start] ^= 0xff
        self.put("corrupt.zip", bytes(data))
        self.assertFalse(cg.Auditor().run(self.root)["complete"])


if __name__ == "__main__":
    unittest.main()
