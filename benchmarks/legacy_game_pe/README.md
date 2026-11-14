# Bintra Benchmark Report: Legacy Win32 Game PE (`generals.exe`)

## Executive Summary
- **Binary Name:** `generals.exe` (Legacy Command & Conquer RTS Game Engine)
- **Architecture:** `PE32 (32-bit)` (`i386 (x86)`)
- **File Size:** `6,480,431 bytes` (~6.18 MB)
- **SHA-256:** `98856e0f439304ac2939c7dfdea21a83be6055b9705c5761d9c8c11bd6e6f0ca`
- **Dependency Verdict:** `HEALTHY` (17/17 DLLs resolved via WOW64 (32-on-64))
- **PE Semantic Self-Similarity:** `100.0%` (x86_prologue_heuristics mode, 500 routines matched)

---

## 1. Spatial Section Anatomy
| Section | Virtual Address | Virtual Size | Raw Size | Shannon Entropy | Executable |
|---|---|---|---|---|---|
| `.text` | `0x1000` | `5,472,256` | `5,470,593` | `6.509` | `True` |
| `.rdata` | `0x539000` | `552,960` | `550,546` | `4.984` | `False` |
| `.data` | `0x5c0000` | `720,896` | `424,419` | `5.723` | `False` |
| `.data1` | `0x670000` | `4,096` | `2,292` | `3.91` | `False` |
| `.rsrc` | `0x671000` | `24,576` | `22,233` | `3.864` | `False` |
| `Px7774` | `0x677000` | `8,239` | `8,239` | `4.624` | `True` |

### Security Mitigations
- **ASLR (Dynamic Base):** `False`
- **DEP / NX Compatibility:** `False`
- **Control Flow Guard (CFG):** `False`
- **Large Address Aware (>2GB VA):** `True`

---

## 2. MSVC RTTI & Forensic Class Extraction
- **Type Descriptors Recovered:** `12`
- **Virtual Function Tables (vftables):** `2`
- **Demangled Class Symbols Sample:**
  - `class INIException`
  - `class .?AW4ErrorCode`
  - `class .?AW4__unnamed`
  - `class exception`
  - `class std::__Named_exception`
  - `class std::logic_error`
  - `class std::out_of_range`
  - `class std::length_error`
  - `class .?AW4SaveCode`
  - `class .?AW4XferStatus`

---

## 3. WOW64 Dependency Audit
- **Loader Subsystem:** `WOW64 (32-on-64)`
- **Resolved Dynamic Libraries (17/17):**
  - `ADVAPI32.DLL` (7 functions imported, KnownDLL=True)
  - `AVIFIL32.DLL` (8 functions imported, KnownDLL=False)
  - `DBGHELP.DLL` (8 functions imported, KnownDLL=False)
  - `DINPUT8.DLL` (1 functions imported, KnownDLL=False)
  - `GDI32.DLL` (18 functions imported, KnownDLL=True)
  - `IMM32.DLL` (12 functions imported, KnownDLL=True)
  - `kernel32.dll` (86 functions imported, KnownDLL=True)
  - `MSVCIRT.DLL` (3 functions imported, KnownDLL=False)
  - `msvcrt.dll` (138 functions imported, KnownDLL=True)
  - `OLEAUT32.DLL` (6 functions imported, KnownDLL=True)
  - `SHELL32.DLL` (3 functions imported, KnownDLL=True)
  - `USER32.dll` (43 functions imported, KnownDLL=True)
  - `WINMM.dll` (3 functions imported, KnownDLL=False)
  - `WSOCK32.DLL` (28 functions imported, KnownDLL=False)
  - `BINKW32.DLL` (11 functions imported, KnownDLL=False)
  - `MSS32.DLL` (60 functions imported, KnownDLL=False)
  - `OLE32.DLL` (6 functions imported, KnownDLL=True)

- **Missing DLLs:** `0`
- **Architecture Mismatches:** `0`

---

## 4. Deobfuscation & Semantic Diffing
- **Opaque Predicates Found in Header Code:** `0`
- **Control Flow Flattening (CFF):** `False`
- **x86 Prologue Heuristic Function Recovery:** `500` routines verified across execution boundary.
