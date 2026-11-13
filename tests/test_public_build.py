import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("public_build", ROOT / "tools/build.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
# Reviewed export baseline: behavior includes actions, selectors, scopes,
# version guards, dependencies and timing; only annotation fields are omitted.
BASELINE = {'APP_IDS_SHA256': '48e68a0f67987a38739a42705feff739dbfb1fcaa486ab9fa4ab8d0382b5a310', 'APP_BEHAVIOR_SHA256': '1c1d2cf49b3e8c83b323d6064116fabcf9d9c5e0f2b6b57eb13059c1b6483441', 'GLOBALS_WITHOUT_APPS_SHA256': '9e66948023e94c3f58ce54edeb12d5f22129ba89a5281a15f3f5e9da6eaca0f6', 'CATEGORIES_SHA256': '7b4a3ff5b09293511a949ffc3dc05b59af7f57ad0935e54c5b62dc112b1c668d', 'SCOPE_SHA256': {'0': '93d77d58d3eae87470987570fe503e4f09978146fbeadeaf828bbe486f83c79b', '1': 'f1946b34c0a40e1e84f9791011a2e6714dd2934852c401a0786c962fdec86fff', '2': '1d237291ae096b5c787a04bf6438d41cad25690a304cdd2df1f18a5566090871'}}
ANNOTATIONS = {"name", "desc", "exampleUrls", "snapshotUrls", "excludeSnapshotUrls"}
SCREENSHOTS = {"exampleUrls", "snapshotUrls", "excludeSnapshotUrls"}


def digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def behavior(value):
    if isinstance(value, dict):
        return {k: behavior(v) for k, v in value.items() if k not in ANNOTATIONS}
    if isinstance(value, list):
        return [behavior(v) for v in value]
    return value


def keys(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from keys(v)
    elif isinstance(value, list):
        for item in value:
            yield from keys(item)


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def copy_sources(destination):
    for name in ["config.json", "categories.json"]:
        shutil.copy2(ROOT / name, destination / name)
    shutil.copytree(ROOT / "rules", destination / "rules")
    (destination / "tools").mkdir()
    shutil.copy2(ROOT / "tools/build.py", destination / "tools/build.py")


class PublicBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = BUILD.make_artifacts(ROOT)
        cls.subscription = json.loads(cls.artifacts["gkd.json5"])
        cls.release = json.loads(cls.artifacts["release.json"])

    def test_public_identity_and_urls(self):
        sub = self.subscription
        expected = {"id": 20261113, "name": "Nisconder的GKD订阅", "version": 8,
                    "author": "Nisconder", "updateUrl": "https://nisconder.pages.dev/gkd/subscription.json5",
                    "checkUpdateUrl": "https://nisconder.pages.dev/gkd/version.json5",
                    "supportUri": "https://github.com/nisconder/Nisconder-GKD-Subscription/issues"}
        self.assertEqual({k: sub[k] for k in expected}, expected)
        self.assertEqual(json.loads(self.artifacts["gkd.version.json5"]), {"id": 20261113, "version": 8})

    def test_complete_app_behavior_preserved(self):
        apps = self.subscription["apps"]
        self.assertEqual(digest(sorted(a["id"] for a in apps)), BASELINE["APP_IDS_SHA256"])
        self.assertEqual(digest(behavior(apps)), BASELINE["APP_BEHAVIOR_SHA256"])

    def test_global_actions_timing_and_protections_preserved(self):
        groups = [{k: v for k, v in g.items() if k != "apps"} for g in self.subscription["globalGroups"]]
        self.assertEqual(digest(groups), BASELINE["GLOBALS_WITHOUT_APPS_SHA256"])
        self.assertEqual(digest(self.subscription["categories"]), BASELINE["CATEGORIES_SHA256"])

    def test_global_default_scope_only_approved_public_apps(self):
        public_ids = {a["id"] for a in self.subscription["apps"]}
        for group in self.subscription["globalGroups"]:
            ids = sorted(a["id"] for a in group["apps"])
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue(set(ids) <= public_ids)
            self.assertEqual(digest(ids), BASELINE["SCOPE_SHA256"][str(group["key"])])
            for flag in ["matchAnyApp", "matchSystemApp", "matchLauncher"]:
                self.assertIs(group[flag], False)
            self.assertNotIn("com.android.thememanager", ids)
            self.assertNotIn("org.example.unsupported", ids)
        # GKD permits users to explicitly override scope. This assertion is
        # about the published defaults, not a promise to override user choices.

    def test_no_screenshot_metadata_or_source_directives(self):
        self.assertFalse(SCREENSHOTS & set(keys(self.subscription)))
        self.assertNotIn("$ref", set(keys(self.subscription)))
        self.assertNotIn("appScopes", set(keys(self.subscription)))
        self.assertNotIn("configuration", self.subscription)
        for file in (ROOT / "rules").rglob("*.json"):
            self.assertFalse(SCREENSHOTS & set(keys(json.loads(file.read_text(encoding="utf-8")))))

    def test_no_local_paths_or_addresses_in_runtime_artifact(self):
        text = self.artifacts["gkd.json5"].decode()
        for marker in ["localhost", "127.0.0.1", "192.168.", "Documents/Codex", "Documents\\Codex", "evidence/", "backups/", "device/", "本机", "临时内存"]:
            self.assertNotIn(marker, text)
        self.assertNotRegex(text, r"(?<![A-Za-z])[A-Za-z]:[\\/](?!/)")

    def test_current_version_guards_and_click_actions(self):
        apps = {a["id"]: a for a in self.subscription["apps"]}
        def group(package, key):
            return next(g for g in apps[package]["groups"] if g["key"] == key)
        x = group("com.twitter.android", 6)
        for rule in x["rules"]:
            if rule.get("key") in [100, 101]:
                self.assertEqual(rule["versionCodes"], [312420001])
                self.assertEqual(rule["action"], "clickNode")
                self.assertIs(rule["fastQuery"], False)
        pdd = next(r for r in group("com.xunmeng.pinduoduo", 8)["rules"] if r.get("key") == 100)
        self.assertEqual(pdd["versionCode"], {"include": [83100]})
        self.assertEqual(pdd["action"], "clickCenter")
        self.assertEqual(group("com.tianyancha.skyeye", 1)["versionCodes"], [161021])
        self.assertEqual(group("com.suda.yzune.wakeupschedule", 5)["rules"][0]["action"], "clickNode")

    def test_rule_shorthand_counted_once_and_preserved(self):
        shorthand = [(a["id"], g["key"]) for a in self.subscription["apps"] for g in a["groups"] if isinstance(g["rules"], str)]
        self.assertEqual(len(shorthand), 5)
        self.assertEqual(self.release["counts"], {"apps": 78, "appGroups": 480, "appRules": 785,
            "globalGroups": 3, "globalRules": 4, "globalAllowedApps": {"0": 45, "1": 46, "2": 34},
            "groupsTotal": 483, "rulesTotal": 789, "globalScopeEntries": 125, "globalScopeAppsUnion": 47})

    def test_release_hashes_are_raw_byte_sha256(self):
        for name, details in self.release["files"].items():
            self.assertEqual(details["sha256"], hashlib.sha256(self.artifacts[name]).hexdigest())
            self.assertEqual(details["bytes"], len(self.artifacts[name]))
            self.assertTrue(self.artifacts[name].endswith(b"\n"))

    def test_committed_outputs_and_clean_checkout_rebuild_identical(self):
        for name, data in self.artifacts.items():
            self.assertEqual(data, (ROOT / "dist" / name).read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            clean = Path(directory)
            copy_sources(clean)
            self.assertEqual({p.name for p in clean.iterdir()}, {"config.json", "categories.json", "rules", "tools"})
            env = dict(os.environ, PYTHONIOENCODING="utf-8")
            subprocess.run([sys.executable, str(clean / "tools/build.py")], cwd=clean, env=env, check=True, capture_output=True)
            for name, data in self.artifacts.items():
                self.assertEqual(data, (clean / "dist" / name).read_bytes())
            self.assertEqual(BUILD.make_artifacts(clean), self.artifacts)

    def invalid_source(self, mutate):
        with tempfile.TemporaryDirectory() as directory:
            clean = Path(directory)
            copy_sources(clean)
            file = clean / "rules/global-groups.json"
            source = json.loads(file.read_text(encoding="utf-8"))
            mutate(source)
            write(file, source)
            with self.assertRaises(BUILD.BuildError):
                BUILD.make_artifacts(clean)

    def test_reject_scope_package_without_public_rules(self):
        self.invalid_source(lambda source: source["appScopes"].update({"org.example.unsupported": [0]}))

    def test_reject_unknown_reference(self):
        self.invalid_source(lambda source: source["groups"][0]["rules"][0].update({"excludeMatches": {"$ref": "unknown"}}))

    def test_reject_unreviewed_default_expansion(self):
        self.invalid_source(lambda source: source["groupDefaults"].update({"matchAnyApp": True}))


if __name__ == "__main__":
    unittest.main()
