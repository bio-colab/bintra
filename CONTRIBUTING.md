# Contributing to REA-Neural

Thank you for your interest in contributing to **REA-Neural**!  
REA-Neural is an open-source, agent-native framework that unites continuous weight-space semantics, symbolic decompilation, deterministic deobfuscation, and Windows system forensics.

We welcome contributions from researchers, reverse engineers, security professionals, and systems programmers of all experience levels.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs & Telemetry Edge-Cases](#reporting-bugs--telemetry-edge-cases)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Code & Algorithm Contributions](#code--algorithm-contributions)
  - [Documentation & Architectural Writeups](#documentation--architectural-writeups)
- [Development Environment Setup](#development-environment-setup)
- [Core Architectural Invariants](#core-architectural-invariants)
  - [1. Fail-Closed Security & Target Immutability](#1-fail-closed-security--target-immutability)
  - [2. Minimal Runtime Dependencies](#2-minimal-runtime-dependencies)
  - [3. Stack Frame Balance Proprioception](#3-stack-frame-balance-proprioception)
- [Testing Guidelines](#testing-guidelines)
- [Commit & Pull Request Conventions](#commit--pull-request-conventions)
- [Community & Communication](#community--communication)

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to `security@bio-colab.org`.

---

## How Can I Contribute?

### Reporting Bugs & Telemetry Edge-Cases
- Before filing an issue, search the [existing issue tracker](https://github.com/bio-colab/rea-neural/issues) to ensure it hasn't been reported or resolved.
- Use the **[Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md)**.
- Include:
  - Windows version (`winver` or build number).
  - Python version (`python --version`).
  - Architecture (x86-64, WOW64, or ARM64).
  - Minimal reproducible example (hex stream, synthetic PE, or sanitized crash log).
  - Full traceback or CLI error JSON output.

### Suggesting Enhancements
- Open a feature proposal using the **[Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md)**.
- Check [docs/ROADMAP.md](docs/ROADMAP.md) first to see if the feature is already planned (e.g. native ETW capture sessions, `phnt` NTAPI integration).
- Describe the problem clearly, why existing tools fall short, and how continuous representation or deterministic analysis solves it.

### Code & Algorithm Contributions
Areas where contributions are especially valuable:
- **Continuous Deobfuscator:** Algebraic opaque predicate simplification rules, cadence regularity estimators, instruction boundary recovery.
- **Semantic Function Matching:** Cross-architecture High P-Code IR embeddings, loop-depth topology invariants, normalization across compilers.
- **Windows System Intelligence:** SetupAPI/CfgMgr32 driver lookup enhancements, MiniDump stream decoders, native Event Log parsing.
- **Model Context Protocol (MCP):** Additional agent-native reverse engineering tools conforming to JSON-RPC 2.0.

---

## Development Environment Setup

REA-Neural is designed natively for Windows 10, 11, and Windows Server (with graceful cross-platform fallback for testing on Linux/macOS).

### 1. Fork & Clone
```powershell
git clone https://github.com/<your-username>/rea-neural.git
cd rea-neural
```

### 2. Set Up Virtual Environment (Python 3.10, 3.11, or 3.12)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install in Editable Mode with Development Tools
```powershell
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .
```

Optional test tools:
```powershell
pip install pytest pytest-cov
```

---

## Core Architectural Invariants

Every contribution must preserve REA-Neural's foundational safety and reliability invariants:

### 1. Fail-Closed Security & Target Immutability
- All file mutations are governed by `ExecutionGuard`.
- **Target Immutability:** Never overwrite, truncate, or patch target binaries in-place. All patches and interventions **must** require an explicit, distinct destination path (`--output`).
- Never introduce unrestricted subprocess command execution or shell injection vectors. Read-only Windows commands must pass through the `CommandExecutor` catalog.

### 2. Minimal Runtime Dependencies
- Core binary inspection and deobfuscation modules must rely strictly on the **Python standard library**, `numpy`, and `capstone`.
- Do not introduce heavy deep learning frameworks (PyTorch, TensorFlow) into the core binary path; standalone mode must remain lightweight and instantaneous.

### 3. Stack Frame Balance Proprioception
- Any binary patch logic modifying x86-64 instructions must verify stack frame balance (`RSP`/`RBP` cumulative delta $= 0$).
- Patches must recalculate the PE structural checksum (`SurgicalBinaryPatcher.calculate_pe_checksum`) and maintain virtual boundary alignment.

---

## Testing Guidelines

REA-Neural enforces a **100% pass requirement** on all test suites before any pull request is merged.

### Run Full Test Suite
```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Or via `pytest`:
```powershell
pytest tests -q
```

### Adding New Tests
- If you fix a bug, add a regression test in `tests/test_suite.py` or `tests/test_security_remediation.py` that fails before your fix and passes after.
- If you introduce a new feature, provide unit tests covering:
  1. Standard canonical execution.
  2. Edge cases (empty buffers, boundary values, malformed inputs).
  3. Negative test cases (invalid architectures, corrupt headers, untrusted paths).

---

## Commit & Pull Request Conventions

### Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` A new feature or capability.
- `fix:` A bug fix or patch.
- `docs:` Documentation additions or updates.
- `test:` Adding or updating tests.
- `refactor:` Code refactoring without changing functionality.
- `perf:` Performance improvements.

> [!IMPORTANT]
> **Proprietary & Game Target Anonymity Rule:**  
> Never mention specific commercial proprietary game titles, protected anti-cheat brands, or closed-source commercial product names in git commit messages, branch names, or pull request descriptions. Refer to targets neutrally (e.g. `x86-64 target binary`, `PE32+ executable`, `hybrid embedded ONNX runtime`).

### Pull Request Checklist
1. Open PR against the `main` branch.
2. Complete the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
3. Ensure all automated GitHub Actions CI checks (`Windows Native CI`) pass.
4. Keep PRs focused; split large refactors into smaller, reviewable increments.

---

## Community & Communication

- **GitHub Issues:** For bug reports, feature discussions, and technical roadmap tracking.
- **GitHub Discussions:** For questions, architectural brainstorming, and community sharing.
- **Security:** For confidential vulnerability disclosures, email `security@bio-colab.org`.
