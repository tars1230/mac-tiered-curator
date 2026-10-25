#!/usr/bin/env python3
"""
Unit tests for mac-tiered-curator (`scripts/curator.py`).
Covers all security and functional requirements identified during Cline & OpenCode reviews:
1. Protected root & subtree prefix protection (`~/Documents/*`, `~/Desktop/*`, `~/CloudMounts/*`).
2. Out-of-bounds symlink escape prevention (`~/evil_link -> /System/Library` rejected).
3. Kernel `statfs` local filesystem detection (`get_filesystem_info` / `is_local_filesystem`).
4. Symlink-topology preservation during cleanup (cleans inside target without unlinking the symlink itself).
5. Atomic broken symlink detection & cross-volume re-targeting (`os.replace`).
6. Project marker build artifact discovery (`Cargo.toml` -> `target`).
7. macOS Container leftover detection via `.com.apple.containermanagerd.metadata.plist`.
8. SQLite freelist bloat calculation & lock-safe `vacuum_sqlite_database_safe`.
"""

import json
import os
import plistlib
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import curator  # noqa: E402


class TestMacTieredCurator(unittest.TestCase):
    def test_safety_guardrails_and_subtree_protection(self) -> None:
        self.assertFalse(curator.is_safe_to_modify("/"))
        self.assertFalse(curator.is_safe_to_modify("/System"))
        self.assertFalse(curator.is_safe_to_modify(str(Path.home())))
        self.assertFalse(curator.is_safe_to_modify(str(Path.home() / "Documents")))
        # Subtree protection: descendants of ~/Documents, ~/Desktop, ~/Pictures must also be blocked!
        self.assertFalse(curator.is_safe_to_modify(str(Path.home() / "Documents" / "important_project")))
        self.assertFalse(curator.is_safe_to_modify(str(Path.home() / "Desktop" / "work_notes")))
        self.assertFalse(curator.is_safe_to_modify(str(Path.home() / "Pictures" / "family")))
        self.assertFalse(curator.is_safe_to_modify(str(Path.home() / "CloudMounts" / "123pan" / "cache")))
        # Allowed cache paths
        self.assertTrue(curator.is_safe_to_modify(str(Path.home() / ".workbuddy" / "logs")))
        self.assertTrue(curator.is_safe_to_modify("/Volumes/Cache/openclaw"))

    def test_symlink_escape_rejected(self) -> None:
        """A symlink inside ~ pointing to /System or ~/Documents/secret must be rejected."""
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            escape_sys = os.path.join(tmp_root, "escape_to_system")
            os.symlink("/System/Library", escape_sys)
            self.assertFalse(
                curator.is_safe_to_modify(escape_sys),
                "Symlink inside home pointing to /System/Library must be blocked!",
            )

            escape_docs = os.path.join(tmp_root, "escape_to_docs")
            os.symlink(str(Path.home() / "Documents" / "secret"), escape_docs)
            self.assertFalse(
                curator.is_safe_to_modify(escape_docs),
                "Symlink inside home pointing into ~/Documents must be blocked!",
            )

    def test_statfs_local_filesystem_detection(self) -> None:
        info = curator.get_filesystem_info(str(Path.home()))
        self.assertIsNotNone(info)
        fstype, is_local, mnton = info  # type: ignore[misc]
        self.assertTrue(is_local)
        self.assertEqual(fstype, "apfs")
        self.assertTrue(curator.is_local_filesystem(str(Path.home())))

    def test_symlink_topology_preserved_during_clean(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            external_target = os.path.join(tmp_root, "external_cache_vol")
            os.makedirs(external_target)
            dummy_file = os.path.join(external_target, "stale.log")
            with open(dummy_file, "wb") as f:
                f.write(b"x" * 16384)

            symlink_path = os.path.join(tmp_root, "symlinked_cache")
            os.symlink(external_target, symlink_path)

            # Dry run first
            _, cnt_dry = curator.clean_directory_contents_preserving_root(symlink_path, dry_run=True)
            self.assertEqual(cnt_dry, 1)
            self.assertTrue(os.path.exists(dummy_file))
            self.assertTrue(os.path.islink(symlink_path))

            # Actual execution: must keep symlink intact while removing inner file
            _, cnt = curator.clean_directory_contents_preserving_root(symlink_path, dry_run=False)
            self.assertEqual(cnt, 1)
            self.assertTrue(os.path.islink(symlink_path), "Symlink itself must never be deleted!")
            self.assertTrue(os.path.isdir(external_target), "Target directory root must remain intact!")
            self.assertFalse(os.path.exists(dummy_file), "Inner cache file must be deleted!")

    def test_broken_symlink_detection_and_atomic_repair(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            old_vol = os.path.join(tmp_root, "OldDataPool")
            new_vol = os.path.join(tmp_root, "NewDatabox")
            os.makedirs(os.path.join(new_vol, "archive"))
            migrated_file = os.path.join(new_vol, "archive", "demo.mp4")
            with open(migrated_file, "wb") as f:
                f.write(b"video")

            search_dir = os.path.join(tmp_root, "Downloads")
            os.makedirs(search_dir)
            broken_link = os.path.join(search_dir, "demo.mp4")
            os.symlink(os.path.join(old_vol, "archive", "demo.mp4"), broken_link)

            records = curator.scan_broken_symlinks(
                search_roots=[search_dir],
                replacement_candidates=[(old_vol + "/", new_vol + "/")],
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].status, "repairable")
            self.assertEqual(records[0].suggested_new_target, migrated_file)

            stats = curator.repair_or_remove_broken_symlinks(records, dry_run=False)
            self.assertEqual(stats["repaired"], 1)
            self.assertEqual(os.readlink(broken_link), migrated_file)
            self.assertTrue(os.path.exists(broken_link))

    def test_project_marker_artifact_scanner(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            proj = os.path.join(tmp_root, "my_rust_app")
            target_dir = os.path.join(proj, "target")
            os.makedirs(target_dir)
            with open(os.path.join(proj, "Cargo.toml"), "w") as f:
                f.write("[package]\nname = 'demo'\n")
            big_blob = os.path.join(target_dir, "libdemo.rlib")
            with open(big_blob, "wb") as f:
                f.write(b"0" * (11 * 1024 * 1024))

            old_time = time.time() - (10 * 86400)
            os.utime(target_dir, (old_time, old_time))

            findings = curator.scan_project_artifacts(roots=[tmp_root], min_stale_days=7, max_depth=2)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule_id"], "project.rust")
            self.assertEqual(findings[0]["artifact_path"], target_dir)

    def test_container_leftovers_detection(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            container_dir = os.path.join(tmp_root, "com.example.uninstalledapp")
            os.makedirs(container_dir)
            meta_plist = os.path.join(container_dir, ".com.apple.containermanagerd.metadata.plist")
            plist_data = {
                "MCMMetadataIdentifier": "com.example.uninstalledapp",
                "MCMMetadataInfo": {
                    "SandboxProfileDataValidationInfo": {
                        "SandboxProfileDataValidationInfoParameters": {
                            "application_bundle_id": "com.example.uninstalledapp",
                            "application_bundle": "/Applications/NonExistentUninstalledApp.app",
                        }
                    }
                },
            }
            with open(meta_plist, "wb") as f:
                plistlib.dump(plist_data, f)
            with open(os.path.join(container_dir, "cache.bin"), "wb") as f:
                f.write(b"A" * (2 * 1024 * 1024))

            leftovers = curator.scan_container_leftovers(
                containers_root=tmp_root,
                installed_bundle_ids={"com.apple.Safari"},
            )
            self.assertEqual(len(leftovers), 1)
            self.assertEqual(leftovers[0]["application_bundle_id"], "com.example.uninstalledapp")

    def test_sqlite_freelist_analysis_and_safe_vacuum(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            # Also test path with space & question mark in name for URI quoting
            db_path = os.path.join(tmp_root, "test space.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE t (data TEXT);")
            conn.execute("INSERT INTO t VALUES (?);", ("A" * 100000,))
            conn.commit()
            conn.execute("DELETE FROM t;")
            conn.commit()
            conn.close()

            res = curator.analyze_sqlite_databases([db_path])
            self.assertEqual(len(res), 1)
            self.assertGreater(res[0]["freelist_pages"], 0)
            self.assertGreater(res[0]["reclaimable_bytes"], 0)

            vac = curator.vacuum_sqlite_database_safe(db_path, dry_run=False)
            self.assertEqual(vac["status"], "vacuumed")
            res_after = curator.analyze_sqlite_databases([db_path])
            self.assertEqual(res_after[0]["freelist_pages"], 0)

    def test_cold_tier_archive_migration_and_symlink_backstop(self) -> None:
        """Verifies `move+symlink` and `move_cold` archive migration with parity verification and manifest ledger."""
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            src_dir = os.path.join(tmp_root, "cold_workspace")
            os.makedirs(src_dir)
            payload_file = os.path.join(src_dir, "artifact.bin")
            with open(payload_file, "wb") as f:
                f.write(b"Z" * 32768)

            vault_dir = os.path.join(tmp_root, "vault")
            manifest_dir = os.path.join(vault_dir, "_manifests")
            os.makedirs(vault_dir)

            rules = [
                {
                    "id": "test.archive-workspace",
                    "op": "move+symlink",
                    "min_age_days": 0,
                    "description": "Test move+symlink",
                    "sources": [src_dir],
                    "dest_subdir": "workspaces",
                }
            ]
            cands = curator.scan_archive_candidates(
                rules=rules,
                archive_vault_root=vault_dir,
                databox_fallback_root=vault_dir,
            )
            self.assertEqual(len(cands), 1)
            self.assertEqual(cands[0].file_count, 1)

            # Dry-run must not modify source
            res_dry = curator.execute_archive_migration(cands, dry_run=True, manifest_dir=manifest_dir)
            self.assertTrue(res_dry["dry_run"])
            self.assertFalse(os.path.islink(src_dir))

            # Apply migration: source becomes symlink -> vault, file verified, manifest written
            res_apply = curator.execute_archive_migration(cands, dry_run=False, manifest_dir=manifest_dir)
            self.assertFalse(res_apply["dry_run"])
            self.assertTrue(os.path.islink(src_dir))
            self.assertTrue(os.path.isfile(os.path.join(src_dir, "artifact.bin")))
            self.assertIsNotNone(res_apply["manifest_path"])
            self.assertTrue(os.path.isfile(res_apply["manifest_path"]))

    def test_archive_collision_and_mount_guard(self) -> None:
        """Verifies unmounted /Volumes guard and collision-free timestamp naming when archiving duplicate filenames."""
        self.assertFalse(curator.is_archive_destination_ready("/Volumes/NonExistentUnmountedDisk_999/archive"))
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            vault_dir = os.path.join(tmp_root, "vault")
            dest_subdir = os.path.join(vault_dir, "downloads-cold")
            os.makedirs(dest_subdir)

            # Pre-existing archived file with the same name
            existing_dest = os.path.join(dest_subdir, "installer.dmg")
            with open(existing_dest, "wb") as f:
                f.write(b"OLD_VERSION")

            # New source file with identical basename
            src_file = os.path.join(tmp_root, "installer.dmg")
            with open(src_file, "wb") as f:
                f.write(b"NEW_VERSION" * 1024)

            cand = curator.ArchiveCandidate(
                rule_id="test.collision",
                op="move_cold",
                description="Collision test",
                source_path=src_file,
                source_volume="/System/Volumes/Data",
                dest_path=existing_dest,
                dest_volume="/Volumes/archive",
                allocated_bytes=11264,
                file_count=1,
                internal_symlinks=0,
                age_days=30.0,
            )
            res = curator.execute_archive_migration(
                [cand], dry_run=False, manifest_dir=os.path.join(vault_dir, "_manifests")
            )
            self.assertEqual(len(res["actions"]), 1)
            actual_dest = res["actions"][0]["dest"]
            self.assertNotEqual(actual_dest, existing_dest)
            self.assertTrue(os.path.isfile(existing_dest))
            self.assertTrue(os.path.isfile(actual_dest))
            with open(existing_dest, "rb") as f:
                self.assertEqual(f.read(), b"OLD_VERSION")

    def test_prune_bundle_migrations(self) -> None:
        """Verifies N-keep-2 rotation of *.BundleMigration backups and stale workdir pruning."""
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            bm = os.path.join(tmp_root, "com.tencent.workbuddy.BundleMigration")
            backups_dir = os.path.join(bm, "backups")
            downloads_dir = os.path.join(bm, "downloads")
            os.makedirs(backups_dir)
            os.makedirs(downloads_dir)

            now = time.time()
            # Create 3 backups with distinct mtimes
            b1 = os.path.join(backups_dir, "v1.backup.app")
            b2 = os.path.join(backups_dir, "v2.backup.app")
            b3 = os.path.join(backups_dir, "v3.backup.app")
            for idx, b in enumerate((b1, b2, b3)):
                os.makedirs(b)
                with open(os.path.join(b, "bin"), "wb") as f:
                    f.write(b"X" * 8192)
                mtime = now - (30 - idx * 10) * 86400
                os.utime(b, (mtime, mtime))

            res = curator.prune_bundle_migrations(caches_root=tmp_root, keep_backups=2, dry_run=False)
            self.assertFalse(os.path.exists(b1))  # oldest pruned
            self.assertTrue(os.path.exists(b2))   # 2nd newest kept
            self.assertTrue(os.path.exists(b3))   # newest kept
            self.assertGreater(res["freed_bytes"], 0)

    def test_prune_cursor_and_updater_versions_with_symlink_pin(self) -> None:
        """Verifies N-keep-2 rotation of Cursor agent-cli versions while protecting symlink-pinned versions."""
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            agent_cli = os.path.join(tmp_root, "agent-cli")
            bin_dir = os.path.join(agent_cli, ".local", "bin")
            versions_dir = os.path.join(agent_cli, ".local", "share", "cursor-agent", "versions")
            runtime_dir = os.path.join(tmp_root, "cursor-runtime")
            cached_data_dir = os.path.join(runtime_dir, "CachedData")
            os.makedirs(bin_dir)
            os.makedirs(versions_dir)
            os.makedirs(cached_data_dir)

            now = time.time()
            # Create 4 versions: v1 (oldest, but pinned by symlink!), v2 (2nd oldest, should be pruned), v3, v4 (newest 2)
            for idx, vname in enumerate(("v1-pinned", "v2-old", "v3-recent", "v4-latest")):
                vpath = os.path.join(versions_dir, vname)
                os.makedirs(vpath)
                bin_file = os.path.join(vpath, "cursor-agent")
                with open(bin_file, "wb") as f:
                    f.write(b"B" * 8192)
                mtime = now - (40 - idx * 10) * 86400
                os.utime(vpath, (mtime, mtime))

            # Pin v1-pinned via .local/bin/cursor-agent symlink
            os.symlink(
                os.path.join(versions_dir, "v1-pinned", "cursor-agent"),
                os.path.join(bin_dir, "cursor-agent"),
            )

            # Create 3 CachedData commit subdirs
            for idx, cname in enumerate(("commit1", "commit2", "commit3")):
                cpath = os.path.join(cached_data_dir, cname)
                os.makedirs(cpath)
                with open(os.path.join(cpath, "v8.bin"), "wb") as f:
                    f.write(b"C" * 4096)
                mtime = now - (30 - idx * 10) * 86400
                os.utime(cpath, (mtime, mtime))

            res = curator.prune_cursor_and_updater_versions(
                agent_cli_root=agent_cli,
                cursor_runtime_root=runtime_dir,
                keep_versions=2,
                dry_run=False,
            )
            self.assertIn("v1-pinned", res["pinned_versions"])
            self.assertTrue(os.path.exists(os.path.join(versions_dir, "v1-pinned")))
            self.assertFalse(os.path.exists(os.path.join(versions_dir, "v2-old")))
            self.assertTrue(os.path.exists(os.path.join(versions_dir, "v3-recent")))
            self.assertTrue(os.path.exists(os.path.join(versions_dir, "v4-latest")))
            self.assertFalse(os.path.exists(os.path.join(cached_data_dir, "commit1")))
            self.assertTrue(os.path.exists(os.path.join(cached_data_dir, "commit2")))
            self.assertTrue(os.path.exists(os.path.join(cached_data_dir, "commit3")))


    def _auto_safe_dirs(self):
        root = tempfile.TemporaryDirectory(dir=str(Path.home()))
        self.addCleanup(root.cleanup)
        base = root.name
        vault = os.path.join(base, "vault")
        os.makedirs(vault)
        return base, vault

    def test_auto_safe_prefixes_and_notification_gate(self) -> None:
        self.assertEqual(curator._auto_safe_prefix_block("/Volumes/DataPool/app/x"), "datapool")
        self.assertEqual(curator._auto_safe_prefix_block(str(Path.home() / "Documents" / "x")), "documents")
        self.assertEqual(curator._auto_safe_prefix_block(str(Path.home() / ".hermes" / "state.db")), "hermes")
        self.assertEqual(curator._auto_safe_prefix_block(str(Path.home() / "CloudMounts" / "123pan")), "network_volume")
        self.assertIsNone(curator._auto_safe_prefix_block(str(Path.home() / ".cache" / "hermes-npm-cache")))
        self.assertIsNone(curator.system_disk_notification([
            curator.VolumeStatus("/Volumes/Cache", "t", "apfs", True, 100, 95, 5, 95.0, "critical"),
            curator.VolumeStatus("/System/Volumes/Data", "t", "apfs", True, 100, 70, 30, 76.0, "healthy"),
        ]))
        message = curator.system_disk_notification([
            curator.VolumeStatus("/System/Volumes/Data", "t", "apfs", True, 100, 82, 18, 82.0, "critical"),
        ])
        self.assertIn("/System/Volumes/Data", message)
        self.assertIn("82.0%", message)
        self.assertIn("18", message)
        self.assertNotIn("清理", message)

    def test_partition_excludes_hermes_move_cold_and_documents(self) -> None:
        rules = [
            {"id": "archive.hermes-checkpoints", "op": "move+symlink", "sources": ["~/.hermes/checkpoints"]},
            {"id": "archive.downloads-cold-installers", "op": "move_cold", "sources": ["/tmp/unused"]},
            {"id": "archive.cache-cold-ml", "op": "move+symlink", "sources": [str(Path.home() / "Documents" / "nope")]},
            {"id": "archive.cache-cold-unity", "op": "move+symlink", "sources": ["/Volumes/Cache/app/Unity"]},
        ]
        allowed, holds = curator.partition_auto_safe_rules(rules, curator.AUTO_SAFE_ARCHIVE_IDS)
        self.assertEqual([rule["id"] for rule in allowed], ["archive.cache-cold-unity"])
        by_id = {row["id"]: row for row in holds}
        self.assertEqual(by_id["archive.hermes-checkpoints"]["reason"], "已排除")
        self.assertIsNone(by_id["archive.hermes-checkpoints"]["bytes"])
        self.assertEqual(by_id["archive.downloads-cold-installers"]["reason"], "不可恢复删除")
        self.assertEqual(by_id["archive.cache-cold-ml"]["reason"], "落入禁止集")

    def test_auto_safe_dry_run_and_apply_move_symlink_only(self) -> None:
        base, vault = self._auto_safe_dirs()
        src = os.path.join(base, "cold_workspace")
        os.makedirs(src)
        with open(os.path.join(src, "artifact.bin"), "wb") as handle:
            handle.write(b"Z" * 32768)
        rule = {
            "id": "test.move",
            "op": "move+symlink",
            "min_age_days": 0,
            "description": "test",
            "sources": [src],
            "dest_subdir": "workspaces",
        }
        cold = {
            "id": "test.cold",
            "op": "move_cold",
            "min_age_days": 0,
            "description": "no link",
            "sources": [os.path.join(base, "installer.dmg")],
            "dest_subdir": "cold",
        }
        with open(cold["sources"][0], "wb") as handle:
            handle.write(b"Q" * 32768)
        backup = os.path.join(base, "backup")
        report = os.path.join(base, "weekly.md")
        dry = curator.run_auto_safe(
            apply=False,
            rules=[rule, cold],
            allow_ids={"test.move", "test.cold"},
            search_roots=[],
            include_live_holds=False,
            backup_root=backup,
            weekly_report_path=report,
            archive_vault_root=vault,
            databox_fallback_root=vault,
            manifest_dir=os.path.join(vault, "_manifests"),
            notify=False,
        )
        self.assertTrue(dry["dry_run"])
        self.assertFalse(os.path.islink(src))
        self.assertTrue(os.path.isdir(src))
        self.assertEqual(len(dry["archive_plans"]), 1)
        self.assertEqual(dry["archive_plans"][0]["file_count"], 1)
        self.assertEqual(dry["archive_plans"][0]["byte_count"], 32768)
        preimage = json.loads(Path(dry["preimage_path"]).read_text(encoding="utf-8"))
        self.assertEqual(preimage["mode"], "dry-run")
        self.assertEqual(preimage["archives"][0]["source"], src)
        self.assertIn("vacuum-sqlite", Path(report).read_text(encoding="utf-8"))
        self.assertIn("不可恢复删除", Path(report).read_text(encoding="utf-8"))
        self.assertFalse(os.path.isdir(os.path.join(vault, "_manifests")))

        applied = curator.run_auto_safe(
            apply=True,
            rules=[rule, cold],
            allow_ids={"test.move", "test.cold"},
            search_roots=[],
            include_live_holds=False,
            backup_root=os.path.join(base, "backup-apply"),
            weekly_report_path=os.path.join(base, "weekly-apply.md"),
            archive_vault_root=vault,
            databox_fallback_root=vault,
            manifest_dir=os.path.join(vault, "_manifests"),
            notify=False,
        )
        self.assertFalse(applied["dry_run"])
        self.assertIsNone(applied["failure"])
        self.assertTrue(os.path.islink(src))
        self.assertEqual(os.readlink(src), applied["archive_plans"][0]["dest"])
        self.assertEqual(Path(os.path.join(src, "artifact.bin")).read_bytes(), b"Z" * 32768)
        self.assertTrue(os.path.isfile(cold["sources"][0]))
        self.assertTrue(os.path.isfile(os.path.join(vault, "_manifests", os.listdir(os.path.join(vault, "_manifests"))[0])))

    def test_auto_safe_parity_failure_keeps_source(self) -> None:
        base, vault = self._auto_safe_dirs()
        src = os.path.join(base, "payload")
        os.makedirs(src)
        with open(os.path.join(src, "artifact.bin"), "wb") as handle:
            handle.write(b"Z" * 32768)
        rule = {
            "id": "test.move",
            "op": "move+symlink",
            "min_age_days": 0,
            "description": "parity",
            "sources": [src],
            "dest_subdir": "workspaces",
        }
        real_copy = curator.copy_archive_payload

        def bad_copy(src_path: str, dest: str) -> None:
            real_copy(src_path, dest)
            with open(os.path.join(dest, "extra.bin"), "wb") as handle:
                handle.write(b"x")

        curator.copy_archive_payload = bad_copy
        try:
            result = curator.run_auto_safe(
                apply=True,
                rules=[rule],
                allow_ids={"test.move"},
                search_roots=[],
                include_live_holds=False,
                backup_root=os.path.join(base, "backup"),
                weekly_report_path=os.path.join(base, "weekly.md"),
                archive_vault_root=vault,
                databox_fallback_root=vault,
                manifest_dir=os.path.join(vault, "_manifests"),
                notify=False,
            )
        finally:
            curator.copy_archive_payload = real_copy
        self.assertEqual(result["exit_code"], 3)
        self.assertTrue(os.path.isdir(src))
        self.assertFalse(os.path.islink(src))
        self.assertTrue(os.path.isfile(os.path.join(src, "artifact.bin")))
        self.assertIn(".incomplete-", result["failure"]["incomplete_path"])
        self.assertTrue(os.path.isdir(result["failure"]["incomplete_path"]))
        self.assertFalse(os.path.exists(result["archive_plans"][0]["dest"]))

    def test_auto_safe_skips_datapool_hermes_and_irreversible_helpers(self) -> None:
        base, vault = self._auto_safe_dirs()
        mirror = os.path.join(base, "mirror", "app", "archives")
        os.makedirs(mirror)
        mirrored = os.path.join(mirror, "missing.bin")
        with open(mirrored, "wb") as handle:
            handle.write(b"m")
        search = os.path.join(base, "links")
        os.makedirs(search)
        link = os.path.join(search, "missing.bin")
        os.symlink("/Volumes/DataPool/app/archives/missing.bin", link)
        orphan = os.path.join(search, "orphan")
        os.symlink("/no/such/curator-auto-safe-target", orphan)
        src = os.path.join(base, "kept")
        os.makedirs(src)
        with open(os.path.join(src, "a.bin"), "wb") as handle:
            handle.write(b"a" * 32768)

        def forbidden_scandir(path):
            if isinstance(path, int):
                return orig_scandir(path)
            norm = os.path.normpath(os.path.abspath(path))
            for prefix in (
                os.path.expanduser("~/.hermes"),
                "/Volumes/DataPool",
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/CloudMounts"),
            ):
                prefix = os.path.normpath(prefix)
                if norm == prefix or norm.startswith(prefix + os.sep):
                    raise AssertionError(norm)
            return orig_scandir(path)

        def boom(*_args, **_kwargs):
            raise AssertionError("irreversible helper called")

        orig_scandir = curator.os.scandir
        saved = {
            "scandir": curator.os.scandir,
            "vacuum": curator.vacuum_sqlite_database_safe,
            "analyze": curator.analyze_sqlite_databases,
            "discover": curator.discover_agent_sqlite_paths,
            "clean": curator.clean_directory_contents_preserving_root,
        }
        curator.os.scandir = forbidden_scandir
        curator.vacuum_sqlite_database_safe = boom
        curator.analyze_sqlite_databases = boom
        curator.discover_agent_sqlite_paths = boom
        curator.clean_directory_contents_preserving_root = boom
        try:
            result = curator.run_auto_safe(
                apply=True,
                rules=[
                    {"id": "archive.hermes-checkpoints", "op": "move+symlink", "min_age_days": 0, "description": "hermes", "sources": ["~/.hermes/checkpoints"], "dest_subdir": "h"},
                    {"id": "test.move", "op": "move+symlink", "min_age_days": 0, "description": "kept", "sources": [src], "dest_subdir": "kept"},
                ],
                allow_ids={"archive.hermes-checkpoints", "test.move"},
                search_roots=[search],
                replacement_candidates=[("/Volumes/DataPool/", os.path.join(base, "mirror") + "/")],
                include_live_holds=False,
                backup_root=os.path.join(base, "backup"),
                weekly_report_path=os.path.join(base, "weekly.md"),
                archive_vault_root=vault,
                databox_fallback_root=vault,
                manifest_dir=os.path.join(vault, "_manifests"),
                notify=False,
            )
        finally:
            curator.os.scandir = saved["scandir"]
            curator.vacuum_sqlite_database_safe = saved["vacuum"]
            curator.analyze_sqlite_databases = saved["analyze"]
            curator.discover_agent_sqlite_paths = saved["discover"]
            curator.clean_directory_contents_preserving_root = saved["clean"]
        self.assertEqual(os.readlink(link), "/Volumes/DataPool/app/archives/missing.bin")
        self.assertEqual(os.readlink(orphan), "/no/such/curator-auto-safe-target")
        self.assertTrue(os.path.islink(src))
        report = Path(os.path.join(base, "weekly.md")).read_text(encoding="utf-8")
        self.assertIn("已排除", report)
        self.assertIn("无本地目标", report)
        self.assertIn("落入禁止集", report)
        self.assertIn("vacuum-sqlite", report)
        self.assertTrue(any(row["reason"] == "无本地目标" for row in result["holds"]))
        self.assertNotIn(link, [plan["link_path"] for plan in result["symlink_plans"]])

    def test_datapool_rewrite_stays_off_when_unmounted(self) -> None:
        base, _vault = self._auto_safe_dirs()
        new_root = os.path.join(base, "new-archive")
        os.makedirs(os.path.join(new_root, "app"))
        target = os.path.join(new_root, "app", "item.bin")
        with open(target, "wb") as handle:
            handle.write(b"t")
        search = os.path.join(base, "search")
        os.makedirs(search)
        link = os.path.join(search, "item.bin")
        os.symlink("/Volumes/DataPool/app/item.bin", link)
        original = curator.os.path.ismount

        def fake_ismount(path: str) -> bool:
            if path == "/Volumes/DataPool":
                return False
            return original(path)

        curator.os.path.ismount = fake_ismount
        try:
            records = curator.scan_broken_symlinks(search_roots=[search], allow_datapool_rewrite=False)
        finally:
            curator.os.path.ismount = original
        self.assertEqual(records[0].status, "orphaned")
        self.assertIsNone(records[0].suggested_new_target)
        self.assertEqual(os.readlink(link), "/Volumes/DataPool/app/item.bin")

    def test_prune_playwright_browser_versions(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            pw_root = os.path.join(tmp_root, "ms-playwright")
            os.makedirs(os.path.join(pw_root, "chromium-1200"), exist_ok=True)
            os.makedirs(os.path.join(pw_root, "chromium-1201"), exist_ok=True)
            os.makedirs(os.path.join(pw_root, "chromium_headless_shell-1200"), exist_ok=True)
            os.makedirs(os.path.join(pw_root, "chromium_headless_shell-1201"), exist_ok=True)
            
            # 写入测试假文件
            with open(os.path.join(pw_root, "chromium-1200", "test.bin"), "wb") as f:
                f.write(b"x" * 1024)
            with open(os.path.join(pw_root, "chromium-1201", "test.bin"), "wb") as f:
                f.write(b"x" * 2048)

            # 调整 mtime: 1200 较旧，1201 较新
            os.utime(os.path.join(pw_root, "chromium-1200"), (1000, 1000))
            os.utime(os.path.join(pw_root, "chromium-1201"), (2000, 2000))
            os.utime(os.path.join(pw_root, "chromium_headless_shell-1200"), (1000, 1000))
            os.utime(os.path.join(pw_root, "chromium_headless_shell-1201"), (2000, 2000))

            # dry_run = True 测试
            dry_res = curator.prune_playwright_browser_versions(playwright_root=pw_root, keep_versions=1, dry_run=True)
            self.assertEqual(len(dry_res["removed_items"]), 2)
            self.assertTrue(os.path.exists(os.path.join(pw_root, "chromium-1200")))

            # dry_run = False 实际执行
            apply_res = curator.prune_playwright_browser_versions(playwright_root=pw_root, keep_versions=1, dry_run=False)
            self.assertEqual(len(apply_res["removed_items"]), 2)
            self.assertFalse(os.path.exists(os.path.join(pw_root, "chromium-1200")))
            self.assertTrue(os.path.exists(os.path.join(pw_root, "chromium-1201")))
            self.assertFalse(os.path.exists(os.path.join(pw_root, "chromium_headless_shell-1200")))
            self.assertTrue(os.path.exists(os.path.join(pw_root, "chromium_headless_shell-1201")))

    def test_clean_chrome_code_sign_clones(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            clone_root = os.path.join(tmp_root, "com.google.Chrome.code_sign_clone")
            active_clone = os.path.join(clone_root, "code_sign_clone.ACTIVE")
            orphan_clone = os.path.join(clone_root, "code_sign_clone.ORPHAN")
            os.makedirs(active_clone, exist_ok=True)
            os.makedirs(orphan_clone, exist_ok=True)

            with open(os.path.join(active_clone, "test.bin"), "wb") as f:
                f.write(b"a" * 1024)
            with open(os.path.join(orphan_clone, "test.bin"), "wb") as f:
                f.write(b"b" * 2048)

            # 模拟 orphan 是 3 小时前创建的
            past = time.time() - 3.0 * 3600
            os.utime(orphan_clone, (past, past))

            # dry_run = True
            dry = curator.clean_chrome_code_sign_clones(
                dry_run=True,
                min_age_hours=2.0,
                test_roots=[clone_root],
                test_active_clones={"code_sign_clone.ACTIVE"},
            )
            self.assertEqual(len(dry["removed_items"]), 1)
            self.assertTrue(os.path.exists(orphan_clone))
            self.assertTrue(os.path.exists(active_clone))

            # dry_run = False
            apply = curator.clean_chrome_code_sign_clones(
                dry_run=False,
                min_age_hours=2.0,
                test_roots=[clone_root],
                test_active_clones={"code_sign_clone.ACTIVE"},
            )
            self.assertEqual(len(apply["removed_items"]), 1)
            self.assertFalse(os.path.exists(orphan_clone))
            self.assertTrue(os.path.exists(active_clone))

    def test_clean_stale_tmp_build_residue(self) -> None:
        with tempfile.TemporaryDirectory(dir=str(Path.home())) as tmp_root:
            old_build = os.path.join(tmp_root, "wbasar_test_dir")
            new_build = os.path.join(tmp_root, "wbasar_fresh_dir")
            other_dir = os.path.join(tmp_root, "unrelated_dir")
            os.makedirs(old_build, exist_ok=True)
            os.makedirs(new_build, exist_ok=True)
            os.makedirs(other_dir, exist_ok=True)

            past = time.time() - 30.0 * 3600  # 30 hours old
            os.utime(old_build, (past, past))

            dry = curator.clean_stale_tmp_build_residue(
                tmp_dir=tmp_root,
                min_age_hours=24.0,
                prefixes=("wbasar",),
                dry_run=True,
            )
            self.assertEqual(len(dry["removed_items"]), 1)
            self.assertTrue(os.path.exists(old_build))

            apply = curator.clean_stale_tmp_build_residue(
                tmp_dir=tmp_root,
                min_age_hours=24.0,
                prefixes=("wbasar",),
                dry_run=False,
            )
            self.assertEqual(len(apply["removed_items"]), 1)
            self.assertFalse(os.path.exists(old_build))
            self.assertTrue(os.path.exists(new_build))
            self.assertTrue(os.path.exists(other_dir))


if __name__ == "__main__":
    unittest.main()



