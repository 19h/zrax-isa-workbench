#!/usr/bin/env python3
"""Shared harvest loop for code corpora built from public GitHub repositories.

Used by pic14_asm_corpus.py and asl_asm_corpus.py (loaded by path: run with
`python3 -I`, which keeps the script directory off sys.path). For each
repository in a TSV (`owner/name<TAB>SPDX license<TAB>branch`), `harvest`
pins the branch head with `git ls-remote`, downloads the tarball from
codeload.github.com and extracts it (paths checked) into WORK/src/, asks the
caller for the programs it can build, writes the distinct programs of one
repository as one sample (OUT/<owner>__<name>.bin, so versions of a program
stay in one train/test group), and appends one provenance row per sample.
The corpus class is the name of OUT.
"""
import hashlib
import io
import os
import re
import subprocess
import tarfile
import urllib.request

DOWNLOAD_TIMEOUT_SECONDS = 60
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MIN_SAMPLE_BYTES = 256


def head_commit(repo, branch):
    """Commit hash of the branch head, from `git ls-remote`."""
    output = subprocess.run(
        ["git", "ls-remote", f"https://github.com/{repo}", f"refs/heads/{branch}"],
        capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT_SECONDS, check=True,
    ).stdout
    return output.split()[0] if output.strip() else None


def extract(tar_bytes, dest):
    """Extract regular files and directories whose paths stay inside dest."""
    root = os.path.realpath(dest)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            target = os.path.realpath(os.path.join(dest, member.name))
            if not target.startswith(root + os.sep):
                continue
            if member.isdir():
                os.makedirs(target, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.extractfile(member) as src, open(target, "wb") as out:
                    out.write(src.read())


def download(repo, commit, dest):
    url = f"https://codeload.github.com/{repo}/tar.gz/{commit}"
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"{repo}: archive over {MAX_DOWNLOAD_BYTES} B")
    extract(data, dest)


# codeload.github.com names an archive's top directory `<name>-<commit>`.
TOP_DIRECTORY = re.compile(r"-([0-9a-f]{40})$")


def downloaded_commit(tree):
    """The commit a tree was downloaded at, from its top directory name, or
    None when it has not been downloaded. Provenance names this commit, not
    the branch head at a later run."""
    if not os.path.isdir(tree):
        return None
    tops = [name for name in os.listdir(tree) if os.path.isdir(os.path.join(tree, name))]
    match = TOP_DIRECTORY.search(tops[0]) if len(tops) == 1 else None
    return match.group(1) if match else None


def read_text(path):
    with open(path, encoding="latin-1") as f:
        return f.read()


def harvest(repos_path, work, out, provenance, programs_of, describe):
    """Build one sample per repository.

    `programs_of(tree)` yields `(relative path, processor, code bytes)` for
    every program it can build; `describe(count, processors)` returns the
    provenance row's "how built" text.
    """
    os.makedirs(out, exist_ok=True)
    corpus_class = os.path.basename(os.path.normpath(out))
    seen = set()
    rows = []
    with open(repos_path) as f:
        repos = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    for repo, license_id, branch in repos:
        slug = repo.replace("/", "__")
        tree = os.path.join(work, "src", slug)
        try:
            commit = downloaded_commit(tree)
            if commit is None:
                commit = head_commit(repo, branch)
                if commit is None:
                    continue
                download(repo, commit, tree)
        except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as e:
            print(f"skip {repo}: {e}")
            continue
        parts, used, processors = [], [], set()
        for relative, processor, code in programs_of(tree):
            digest = hashlib.sha1(code).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            parts.append(code)
            used.append(relative.split(os.sep, 1)[-1])
            processors.add(processor)
        sample = b"".join(parts)
        if len(sample) < MIN_SAMPLE_BYTES:
            print(f"skip {repo}: {len(sample)} B of code")
            continue
        with open(os.path.join(out, slug + ".bin"), "wb") as f:
            f.write(sample)
        basis = license_id if license_id not in ("none", "NOASSERTION") else "public GitHub repo, no license file (weak)"
        rows.append(
            f"| {corpus_class} | {corpus_class}/{slug}.bin | {len(sample)} | https://github.com/{repo}/tree/{commit} "
            f"| {basis} | {describe(len(used), processors)} | real (hobby or course application code) | {repo} |"
        )
        print(f"{repo}: {len(used)} programs, {len(sample)} B", flush=True)
    with open(provenance, "a") as f:
        for row in rows:
            f.write(row + "\n")
