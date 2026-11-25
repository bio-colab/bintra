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


# Repository/src directory (formerly cli.SCRIPT_DIR, used by self-update).
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

    import re
    ref_pat = r"^[a-zA-Z0-9_\./]+[a-zA-Z0-9_\-\./]*$"
    if not re.match(ref_pat, args.branch) or args.branch.startswith("-"):
        print(f"[-] Invalid branch refname: '{args.branch}'")
        sys.exit(1)
    if args.ref and (not re.match(ref_pat, args.ref) or args.ref.startswith("-")):
        print(f"[-] Invalid target ref: '{args.ref}'")
        sys.exit(1)

    import subprocess
    repo_dir = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
    git_dir = os.path.join(repo_dir, ".git")

    if os.path.isdir(git_dir):
        try:
            # Verify git remote configuration before fetching
            remotes_res = subprocess.run(
                ["git", "remote"],
                cwd=repo_dir,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            remotes = [r.strip() for r in remotes_res.stdout.splitlines() if r.strip()] if remotes_res.returncode == 0 else []
            if not remotes or "origin" not in remotes:
                print("[-] No remote 'origin' configured for repository. Update check skipped.")
                return

            print(f"[*] Checking remote repository for updates (branch: '{args.branch}')...")
            fetch_res = subprocess.run(
                ["git", "fetch", "--tags", "origin", "--", args.branch],
                cwd=repo_dir,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            if fetch_res.returncode != 0:
                print(f"[-] Git fetch error: {fetch_res.stderr.strip()}")
                sys.exit(1)

            target_rev = args.ref or f"origin/{args.branch}"
            local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True, encoding="utf-8", errors="replace").strip()
            remote_hash = subprocess.check_output(["git", "rev-parse", "--verify", target_rev], cwd=repo_dir, text=True, encoding="utf-8", errors="replace").strip()

            if local_hash == remote_hash:
                commit_title = subprocess.check_output(["git", "log", "-1", "--format=%s"], cwd=repo_dir, text=True, encoding="utf-8", errors="replace").strip()
                print(f"[+] Bintra is already at the latest commit: {local_hash[:7]} (\"{commit_title}\")")
                return

            incoming_commits = subprocess.check_output(
                ["git", "log", f"HEAD..{remote_hash}", "--oneline"],
                cwd=repo_dir,
                text=True, encoding="utf-8", errors="replace"
            ).strip()
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
                subprocess.run(["git", "merge", "--ff-only", remote_hash], cwd=repo_dir, check=True)
            else:
                print(f"[*] Fast-forwarding latest commits from origin/{args.branch}...")
                subprocess.run(["git", "pull", "--ff-only", "origin", "--", args.branch], cwd=repo_dir, check=True)

            print("[*] Refreshing package entry points and dependencies...")
            subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "-e", "."], cwd=repo_dir, check=True)

            new_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True, encoding="utf-8", errors="replace").strip()
            new_title = subprocess.check_output(["git", "log", "-1", "--format=%s"], cwd=repo_dir, text=True, encoding="utf-8", errors="replace").strip()
            print(f"[+] Successfully updated Bintra to latest commit: {new_hash[:7]} (\"{new_title}\")")
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
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg_spec],
                check=True
            )
            print("[+] Successfully updated Bintra via pip!")
        except Exception as e:
            print(f"[-] Pip update failed: {e}")
            sys.exit(1)

