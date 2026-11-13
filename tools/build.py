#!/usr/bin/env python3
"""Build the public subscription using only this repository and Python's standard library."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse


PACKAGE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")
SCREENSHOT_METADATA = {"exampleUrls", "snapshotUrls", "excludeSnapshotUrls"}
SELECTOR_FIELDS = {"matches", "anyMatches", "excludeMatches", "excludeAllMatches"}
DEFAULT_FIELDS = {
    "fastQuery", "matchRoot", "matchAnyApp", "matchSystemApp", "matchLauncher",
    "actionMaximum", "resetMatch", "matchTime", "forcedTime", "actionCd",
    "priorityTime", "matchDelay", "actionDelay",
}
CONFIG_FIELDS = {
    "schemaVersion", "id", "name", "version", "author", "updateUrl",
    "checkUpdateUrl", "supportUri",
}


class BuildError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object)
    except (OSError, ValueError) as error:
        raise BuildError(f"Cannot read {path.name}: {error}") from error


def encode(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def require_object(value, context):
    if not isinstance(value, dict):
        raise BuildError(f"{context} must be an object")


def require_int(value, context):
    if type(value) is not int:
        raise BuildError(f"{context} must be an integer")


def without_screenshot_metadata(value):
    if isinstance(value, dict):
        return {key: without_screenshot_metadata(item) for key, item in value.items()
                if key not in SCREENSHOT_METADATA}
    if isinstance(value, list):
        return [without_screenshot_metadata(item) for item in value]
    return copy.deepcopy(value)


def check_groups(groups, context):
    if not isinstance(groups, list):
        raise BuildError(f"{context} must be an array")
    seen = set()
    for group in groups:
        require_object(group, context)
        require_int(group.get("key"), f"{context}.key")
        if group["key"] in seen:
            raise BuildError(f"Duplicate group key in {context}: {group['key']}")
        seen.add(group["key"])
        if not isinstance(group.get("name"), str):
            raise BuildError(f"{context}: expected a group name")
        rules = group.get("rules")
        if isinstance(rules, str):
            if not rules.strip():
                raise BuildError(f"{context}: empty shorthand selector")
            continue
        if not isinstance(rules, list):
            raise BuildError(f"{context}: expected a selector string or rules array")
        explicit_keys = set()
        for rule in rules:
            if isinstance(rule, str) and rule.strip():
                continue
            require_object(rule, f"{context}.rules")
            if "key" in rule:
                require_int(rule["key"], f"{context}.rules.key")
                if rule["key"] in explicit_keys:
                    raise BuildError(f"Duplicate explicit rule key in {context}")
                explicit_keys.add(rule["key"])


def load_apps(root: Path):
    folder = root / "rules/apps"
    files = sorted(folder.glob("*.json"))
    if not files:
        raise BuildError("No public app rule files")
    apps = []
    seen = set()
    for file in files:
        if file.is_symlink():
            raise BuildError("App source symlinks are not supported")
        app = without_screenshot_metadata(read_json(file))
        require_object(app, file.name)
        package = app.get("id")
        if not isinstance(package, str) or not PACKAGE.fullmatch(package) or package != file.stem:
            raise BuildError(f"App id must equal its package filename: {file.name}")
        if package in seen:
            raise BuildError(f"Duplicate app id: {package}")
        seen.add(package)
        check_groups(app.get("groups"), f"{package}.groups")
        apps.append(app)
    return apps


def rule_count(group):
    return 1 if isinstance(group["rules"], str) else len(group["rules"])


def expand_globals(source, app_ids):
    require_object(source, "global source")
    if source.get("formatVersion") != 1:
        raise BuildError("Unsupported global source formatVersion")
    if set(source) - {"formatVersion", "groupDefaults", "selectorDefinitions", "groups", "appScopes"}:
        raise BuildError("Unknown global source field")
    defaults = source.get("groupDefaults", {})
    definitions = source.get("selectorDefinitions", {})
    scopes = source.get("appScopes", {})
    for value, name in [(defaults, "groupDefaults"), (definitions, "selectorDefinitions"), (scopes, "appScopes")]:
        require_object(value, name)
    if set(defaults) - DEFAULT_FIELDS:
        raise BuildError("Unknown groupDefaults field")
    for name, definition in definitions.items():
        values = definition if isinstance(definition, list) else [definition]
        if not isinstance(name, str) or not name or not values or any(not isinstance(item, str) or not item.strip() for item in values):
            raise BuildError("Selector definitions must be nonempty strings or string arrays")
    groups = source.get("groups")
    check_groups(groups, "global groups")
    group_keys = {group["key"] for group in groups}
    for package, keys in scopes.items():
        if package not in app_ids:
            raise BuildError(f"Global scope package is not a public supported app: {package}")
        if not isinstance(keys, list) or not keys or any(type(key) is not int for key in keys):
            raise BuildError(f"Invalid scope keys for {package}")
        if len(set(keys)) != len(keys) or set(keys) - group_keys:
            raise BuildError(f"Duplicate or unknown scope keys for {package}")

    def expand(value, field=None):
        if isinstance(value, list):
            return [expand(item) for item in value]
        if not isinstance(value, dict):
            return copy.deepcopy(value)
        if "$ref" in value:
            name = value["$ref"]
            if field not in SELECTOR_FIELDS or set(value) != {"$ref"} or name not in definitions:
                raise BuildError(f"Invalid selector reference: {name!r}")
            return copy.deepcopy(definitions[name])
        if any(str(key).startswith("$") for key in value):
            raise BuildError("Unknown source directive")
        return {key: expand(item, key) for key, item in value.items()}

    result = []
    for group in groups:
        if "apps" in group or set(group) & SELECTOR_FIELDS:
            raise BuildError("Global groups use appScopes and rule-level selectors")
        compiled = expand({**copy.deepcopy(defaults), **group})
        for flag in ["matchAnyApp", "matchSystemApp", "matchLauncher"]:
            if compiled.get(flag) is not False:
                raise BuildError(f"Public default policy requires {flag}=false")
        compiled["apps"] = [{"id": package} for package in sorted(scopes)
                            if group["key"] in scopes[package]]
        result.append(compiled)
    return without_screenshot_metadata(result)


def make_artifacts(root: Path) -> dict[str, bytes]:
    """Return deterministic runtime artifacts without writing files."""
    root = Path(root)
    config = read_json(root / "config.json")
    require_object(config, "config")
    if set(config) != CONFIG_FIELDS or config.get("schemaVersion") != 1:
        raise BuildError("Unexpected public config schema")
    for key in ["id", "version"]:
        require_int(config[key], f"config.{key}")
        if config[key] < 1:
            raise BuildError(f"config.{key} must be positive")
    for key in ["name", "author"]:
        if not isinstance(config[key], str) or not config[key].strip():
            raise BuildError(f"config.{key} must be a nonempty string")
    for key in ["updateUrl", "checkUpdateUrl", "supportUri"]:
        parsed = urlparse(config[key])
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise BuildError(f"config.{key} must be an HTTPS URL without credentials")
    categories = read_json(root / "categories.json")
    if not isinstance(categories, list):
        raise BuildError("categories must be an array")
    category_keys = []
    for category in categories:
        require_object(category, "category")
        require_int(category.get("key"), "category.key")
        category_keys.append(category["key"])
    if len(set(category_keys)) != len(category_keys):
        raise BuildError("Duplicate category keys")
    apps = load_apps(root)
    globals_ = expand_globals(read_json(root / "rules/global-groups.json"), {app["id"] for app in apps})
    subscription = {key: config[key] for key in ["id", "name", "version", "author", "updateUrl", "checkUpdateUrl", "supportUri"]}
    subscription.update(categories=categories, globalGroups=globals_, apps=apps)
    artifacts = {
        "gkd.json5": encode(subscription),
        "gkd.version.json5": encode({"id": config["id"], "version": config["version"]}),
    }
    release = {
        "id": config["id"], "name": config["name"], "version": config["version"],
        "counts": {
            "apps": len(apps), "appGroups": sum(len(app["groups"]) for app in apps),
            "appRules": sum(rule_count(group) for app in apps for group in app["groups"]),
            "globalGroups": len(globals_), "globalRules": sum(rule_count(group) for group in globals_),
            "globalAllowedApps": {str(group["key"]): len(group["apps"]) for group in globals_},
            "groupsTotal": sum(len(app["groups"]) for app in apps) + len(globals_),
            "rulesTotal": sum(rule_count(group) for app in apps for group in app["groups"]) + sum(rule_count(group) for group in globals_),
            "globalScopeEntries": sum(len(group["apps"]) for group in globals_),
            "globalScopeAppsUnion": len({app["id"] for group in globals_ for app in group["apps"]}),
        },
        "files": {name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
                  for name, content in artifacts.items()},
    }
    artifacts["release.json"] = encode(release)
    return artifacts


def build(root: Path):
    artifacts = make_artifacts(root)
    destination = Path(root) / "dist"
    destination.mkdir(parents=True, exist_ok=True)
    # Parsing and validation finish before any previously successful output is replaced.
    for name, content in artifacts.items():
        (destination / name).write_bytes(content)
    return json.loads(artifacts["release.json"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        report = build(args.root)
    except (BuildError, OSError, TypeError) as error:
        parser.exit(1, f"Build failed: {error}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
