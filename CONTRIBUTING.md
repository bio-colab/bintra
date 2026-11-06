# Contributing to REA-Neural

We welcome contributions to **REA-Neural**! Whether you are improving continuous deobfuscation algorithms, expanding Windows PE analysis capabilities, or adding new test cases, your help is appreciated.

## Development Workflow

1. Fork the repository on GitHub.
2. Clone your fork locally on Windows:
   ```powershell
   git clone https://github.com/bio-colab/rea-neural.git
   cd rea-neural
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Run tests:
   ```powershell
   python tests/test_suite.py
   ```
5. Ensure all Windows Native CI checks pass.
6. Submit a Pull Request.

## Code Standards
- Keep core binary inspection modules zero-dependency (rely only on Python standard libraries and numpy).
- Ensure memory-mapped IO (`mmap`) is used when reading large executable sections.
- Verify stack integrity invariance for any binary patching logic.
