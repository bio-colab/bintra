"""Bintra CLI commands: MCP server launcher and self-update."""
import argparse
import os
import sys




def cmd_mcp(cmd: str) -> None:
    """bintra mcp, mcp-server"""
    from mcp_server import main as mcp_main
    mcp_main()
    return


def cmd_update(cmd: str) -> None:
    """bintra update, self-update"""
    _handle_update()


from pathlib import Path
import re
import subprocess


_GIT_LOCAL_TIMEOUT = 15
_GIT_NETWORK_TIMEOUT = 60
_PIP_TIMEOUT = 180

# Repository/src directory (formerly cli.SCRIPT_DIR, used by self-update).
SCRIPT_DIR = str(Path(__file__).resolve().parents[2])
REPO_ROOT = str(Path(__file__).resolve().parents[3])


def _run_subprocess(cmd, cwd=None, timeout: int = _GIT_LOCAL_TIMEOUT, check: bool = True) -> subprocess.CompletedProcess:
    """Run a bounded maintenance subprocess cleanly with explicit timeout handling."""
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=check,
    )


def _git_output(args, cwd: str, timeout: int = _GIT_LOCAL_TIMEOUT) -> str:
    """Return stripped stdout from a bounded local git command."""
    return _run_subprocess(["git", *args], cwd=cwd, timeout=timeout, check=True).stdout.strip()


def _handle_update() -> None:
    parser = argparse.ArgumentParser(
        prog="bintra update",
        description="Check and safely update Bintra from GitHub (requires --yes/--confirm to modify installation)"
    )
    parser.add_argument("--check", action="store_true", help="Check for available updates without applying them")
    parser.add_argument("--branch", default="main", help="Target git branch (default: main)")
    parser.add_argument("--ref", default=None, help="Optional pinned tag or commit SHA to verify/checkout on update")
    parser.add_argument("--yes", "--confirm", dest="confirm", action="store_true", help="Explicit confirmation required to apply updates")
    args = parser.parse_args(sys.argv[2:])

    ref_pat = r"^[a-zA-Z0-9_\./]+[a-zA-Z0-9_\-\./]*$"
    if not re.match(ref_pat, args.branch) or args.branch.startswith("-"):
        print(f"[-] Invalid branch refname: '{args.branch}'")
        sys.exit(1)
    if args.ref and (not re.match(ref_pat, args.ref) or args.ref.startswith("-")):
        print(f"[-] Invalid target ref: '{args.ref}'")
        sys.exit(1)

    repo_dir = REPO_ROOT
    git_dir = os.path.join(repo_dir, ".git")

    if os.path.isdir(git_dir):
        try:
            remotes_res = _run_subprocess(["git", "remote"], cwd=repo_dir, timeout=_GIT_LOCAL_TIMEOUT, check=False)
            remotes = [r.strip() for r in remotes_res.stdout.splitlines() if r.strip()] if remotes_res.returncode == 0 else []
            if not remotes or "origin" not in remotes:
                print("[-] No remote 'origin' configured for repository. Update check skipped.")
                return

            print(f"[*] Checking remote repository for updates (branch: '{args.branch}')...")
            fetch_res = _run_subprocess(
                ["git", "fetch", "--tags", "origin", "--", args.branch],
                cwd=repo_dir,
                timeout=_GIT_NETWORK_TIMEOUT,
                check=False,
            )
            if fetch_res.returncode != 0:
                print(f"[-] Git fetch error: {fetch_res.stderr.strip()}")
                sys.exit(1)

            target_rev = args.ref or f"origin/{args.branch}"
            local_hash = _git_output(["rev-parse", "HEAD"], cwd=repo_dir)
            remote_hash = _git_output(["rev-parse", "--verify", target_rev], cwd=repo_dir)

            if local_hash == remote_hash:
                commit_title = _git_output(["log", "-1", "--format=%s"], cwd=repo_dir)
                print(f"[+] Bintra is already at the latest commit: {local_hash[:7]} (\"{commit_title}\")")
                return

            incoming_commits = _git_output(["log", f"HEAD..{remote_hash}", "--oneline"], cwd=repo_dir)
            print(f"[!] New updates available ({local_hash[:7]} -> {remote_hash[:7]}):\n")
            for c_line in incoming_commits.splitlines():
                print(f"    • {c_line}")
            print()

            if args.check:
                print("[*] Update check completed. Run 'bintra update --yes' to apply.")
                return

            if not args.confirm:
                print("[!] Refusing unconfirmed remote code update. Re-run with '--yes' (or '--confirm') to apply.")
                sys.exit(2)

            if args.ref:
                print(f"[*] Fast-forwarding to verified ref '{args.ref}' ({remote_hash[:12]})...")
                _run_subprocess(["git", "merge", "--ff-only", remote_hash], cwd=repo_dir, timeout=_GIT_LOCAL_TIMEOUT)
            else:
                print(f"[*] Fast-forwarding latest commits from origin/{args.branch}...")
                _run_subprocess(["git", "pull", "--ff-only", "origin", "--", args.branch], cwd=repo_dir, timeout=_GIT_NETWORK_TIMEOUT)

            print("[*] Refreshing package entry points and dependencies...")
            _run_subprocess([sys.executable, "-m", "pip", "install", "--no-deps", "-e", "."], cwd=repo_dir, timeout=_PIP_TIMEOUT)

            new_hash = _git_output(["rev-parse", "HEAD"], cwd=repo_dir)
            new_title = _git_output(["log", "-1", "--format=%s"], cwd=repo_dir)
            print(f"[+] Successfully updated Bintra to latest commit: {new_hash[:7]} (\"{new_title}\")")
        except subprocess.TimeoutExpired as exc:
            print(f"[-] Automatic update timed out running '{' '.join(exc.cmd) if exc.cmd else 'command'}' after {exc.timeout}s.")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Automatic update failed: {e}")
            sys.exit(1)
    else:
        if args.check:
            print("[*] Package is installed without a local git working tree.")
            print("[*] Run 'bintra update --yes --ref <tag-or-sha>' to reinstall/upgrade directly from GitHub.")
            return

        if not args.confirm:
            print("[!] Refusing unconfirmed remote pip installation. Re-run with '--yes' (optionally '--ref <tag-or-sha>') to apply.")
            sys.exit(2)

        pkg_spec = "git+https://github.com/bio-colab/bintra.git"
        if args.ref:
            pkg_spec = f"{pkg_spec}@{args.ref}"
        print(f"[*] Updating Bintra via pip from {pkg_spec}...")
        try:
            _run_subprocess([sys.executable, "-m", "pip", "install", "--upgrade", pkg_spec], timeout=_PIP_TIMEOUT)
            print("[+] Successfully updated Bintra via pip!")
        except subprocess.TimeoutExpired as exc:
            print(f"[-] Pip update timed out after {exc.timeout}s.")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Pip update failed: {e}")
            sys.exit(1)

