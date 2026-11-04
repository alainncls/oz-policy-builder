#!/usr/bin/env python3
"""Apply the reviewed integration to a clean checkout of the exact supported Pollywallet."""
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess

UPSTREAM = "853b102983699726f918b68d8e42edbba74e65b9"
PATCH_PATHS = {"package.json", "pnpm-lock.yaml", "src/lib/passkey.ts", "src/components/Header.tsx", "vite.config.ts", "vitest.config.ts"}
REQUIRED = {"wallet/package.json", "wallet/package-lock.json", "wallet/overlay/upstream.patch",
            "wallet/overlay/UPSTREAM.md", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE"}
FILE = re.compile(r"[A-Za-z0-9_-]+\.(?:mjs|d\.mts|ts|tsx|css)$")
# The upstream bridge test only: its `.test` suffix is the one dot allowed in a file stem.
TEST_FILE = re.compile(r"policy-builder-[A-Za-z0-9_-]+\.test\.ts$")


class Refused(Exception):
    pass


def git(root, *arguments, data=None):
    result = subprocess.run(["git", "-C", str(root), *arguments], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise Refused("Git precondition failed; use the documented clean checkout and revision")
    return result.stdout


def destination(path):
    if path in {"LICENSE-MIT", "LICENSE-APACHE", "NOTICE"}:
        return "src/policy-builder/" + path
    if path == "wallet/overlay/UPSTREAM.md":
        return "src/policy-builder/UPSTREAM.md"
    if path in {"wallet/package.json", "wallet/package-lock.json"}:
        return "src/policy-builder/" + PurePosixPath(path).name
    parts = PurePosixPath(path).parts
    if len(parts) == 3 and parts[:2] in {("wallet", "server"), ("wallet", "shared")} and FILE.fullmatch(parts[-1]):
        return "src/policy-builder/" + "/".join(parts[1:])
    prefix = "wallet/overlay/files/"
    if path.startswith(prefix):
        relative = path[len(prefix):]
        parts = PurePosixPath(relative).parts
        if (relative == "src/routes/policy-builder.tsx"
                or (len(parts) == 4 and parts[:3] == ("src", "policy-builder", "client") and FILE.fullmatch(parts[-1]))
                or (relative.startswith("src/lib/__tests__/policy-builder") and len(parts) == 4
                    and (FILE.fullmatch(parts[-1]) or TEST_FILE.fullmatch(parts[-1])))):
            return relative
    return None


def apply(repo, revision, checkout):
    repo, checkout = Path(repo).resolve(), Path(checkout).resolve()
    if git(checkout, "rev-parse", "--show-toplevel").decode().strip() != str(checkout):
        raise Refused("destination must be the root of a dedicated checkout")
    if git(checkout, "rev-parse", "HEAD").decode().strip() != UPSTREAM:
        raise Refused("unsupported Pollywallet revision")
    if git(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise Refused("destination must be clean, including untracked files")
    if (checkout / "src/policy-builder").exists() or (checkout / "src/policy-builder").is_symlink():
        raise Refused("integration destination already exists")
    if revision.startswith("-"):
        raise Refused("invalid source revision")
    tree = git(repo, "rev-parse", "--verify", revision + "^{tree}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", tree):
        raise Refused("invalid immutable source tree")
    blobs, seen = {}, set()
    for entry in git(repo, "ls-tree", "-rz", tree).split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, object_id = header.decode().split()
        path = raw_path.decode()
        target = destination(path)
        if path not in REQUIRED and target is None:
            continue
        if mode not in {"100644", "100755"} or kind != "blob":
            raise Refused("integration input must be a regular tracked file")
        size = int(git(repo, "cat-file", "-s", object_id))
        if size > 2 * 1024 * 1024:
            raise Refused("integration input exceeds its bound")
        content = git(repo, "cat-file", "blob", object_id)
        seen.add(path)
        if path == "wallet/overlay/upstream.patch":
            patch = content
        else:
            blobs[target] = content
    if not REQUIRED.issubset(seen) or "src/routes/policy-builder.tsx" not in blobs:
        raise Refused("source revision lacks the complete integration and pinned lock metadata")
    for line in patch.decode().splitlines():
        if line.startswith(("--- ", "+++ ")):
            if line[4:6] not in {"a/", "b/"} or line[6:] not in PATCH_PATHS:
                raise Refused("patch modifies an unsupported upstream path")
    # Git can describe binary changes, renames and modes without ---/+++ headers.
    # Inspect Git's parsed paths as well as textual headers before applying anything.
    if git(checkout, "apply", "--summary", "-", data=patch):
        raise Refused("patch must only edit existing text files")
    entries = git(checkout, "apply", "--numstat", "-z", "-", data=patch).split(b"\0")
    changed = set()
    for entry in entries:
        if not entry:
            continue
        fields = entry.decode().split("\t")
        if (len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit()
                or fields[2] not in PATCH_PATHS or fields[2] in changed):
            raise Refused("patch modifies an unsupported upstream path")
        changed.add(fields[2])
    if not changed:
        raise Refused("patch contains no supported edits")
    for relative in blobs:
        target = checkout / relative
        if target.exists() or target.is_symlink():
            raise Refused("an integration file would overwrite an existing path")
        if any(parent.is_symlink() for parent in target.parents if parent != checkout.parent):
            raise Refused("integration destination contains a symlink")
    git(checkout, "apply", "--check", "--whitespace=error-all", "-", data=patch)
    git(checkout, "apply", "--whitespace=error-all", "-", data=patch)
    for relative, content in blobs.items():
        target = checkout / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o644)
    return tree


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--revision", default="HEAD", help="immutable toolkit commit/tree; defaults to HEAD")
    arguments = parser.parse_args()
    try:
        tree = apply(Path(__file__).resolve().parent.parent, arguments.revision, arguments.checkout)
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, Refused) else "integration apply failed") from None
    print("Integration applied from tree " + tree)
    print("Review the diff, then install the existing upstream lock and nested package lock separately.")


if __name__ == "__main__":
    main()
