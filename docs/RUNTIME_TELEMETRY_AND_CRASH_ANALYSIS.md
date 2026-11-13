# Bintra: Runtime Telemetry, Crash Root-Cause Analysis & Symbiotic Decompiler Bridge
## دليل الهندسة المعمارية والقياس الحي عن بُعد والتحليل الجنائي للأعطال

---

## 1. الهوية الهندسية ونظرة عامة (Executive Overview)

يقدم هذا التوثيق البنية المعمارية الشاملة لمنظومة **القياس الحي عن بُعد (Runtime Telemetry)** والتحليل الجنائي للانهيارات البرمجية والربط التفاعلي المباشر مع بيئات فك التجميع الساكنة (Ghidra Decompiler) في مشروع `Bintra` (الإصدار `v1.0.0+`).

تتكامل المنظومة عبر 4 مراحل هندسية متعاقبة ومترابطة رياضياً وتطبيقياً:
1. **المرحلة الأولى (Phase 1):** فحص وتصنيف بنية الذاكرة الافتراضية للعمليات الحية، وقراءة القيم سلبياً (`PROCESS_VM_READ`)، والبحث الأولي/اللاحق، ومسح سلاسل المؤشرات، واستنتاج بنى البيانات (`VirtualMemoryInspector`, `ProcessMemoryScanner`).
2. **المرحلة الثانية (Phase 2):** محرك التحليل الجنائي المؤتمت للانهيارات مع ربط فحص VAD وتطبيع حقول `MiniDump` (`CrashRootCauseAnalyzer`).
3. **المرحلة الثالثة (Phase 3):** الالتقاط الهجين لأحداث ويندوز عبر ETW الأصلي (`OpenTraceW`/`ProcessTrace`) أو مسارات البديل غير المرفوع (`WEVTAPI`/`CreateToolhelp32Snapshot`)، وتحليل التسلسل الزمني والسببي (`EtwLiveCaptureSession`, `EtwTimelineCorrelator`).
4. **المرحلة الرابعة (Phase 4):** جسر الاتصال المحلي الموثق القائم على الطابور والاستطلاع الدوري (`Queued-Poll JSON-RPC 2.0`) مع Ghidra (`GhidraLiveBridgeServer`, `BintraLiveBridgeService.py`).

```mermaid
flowchart TD
    subgraph S1 ["المرحلة 1: فحص بنية الذاكرة (VAD Spatial Inspection)"]
        VAD["VirtualMemoryInspector"]
        VAD -->|VirtualQueryEx| MAP["ProcessMemoryMapSnapshot"]
        MAP -->|Spatial Classification| CAT["IMAGE_TEXT / HEAP / STACK / NULL_TRAP / W^X"]
    end

    subgraph S2 ["المرحلة 2: التحليل الجنائي للعطل (Automated Crash RCA)"]
        DMP["MiniDump (.dmp)"] --> PARSER["MiniDumpParser (16 GPRs)"]
        PARSER --> RCA["CrashRootCauseAnalyzer"]
        CAT -.->|Bounds Cross-Check| RCA
        DISASM["Capstone Instruction Window"] --> RCA
        RCA --> PROOF["Deterministic Blame Attribution (Null / Poison / UAF)"]
    end

    subgraph S3 ["المرحلة 3: القياس الحي والسببية (ETW Timeline Correlation)"]
        ETW["EtwLiveCaptureSession"] -->|Ring Buffer (FIFO)| EVENTS["EtwEventRecord Stream"]
        EVENTS --> CORR["EtwTimelineCorrelator"]
        CORR --> VERDICT["Temporal Verdict (VirtualFree Churn / Late Injection)"]
    end

    subgraph S4 ["المرحلة 4: جسر غيدرا الحي (Ghidra Live IPC Bridge)"]
        BRIDGE["GhidraLiveBridgeServer (127.0.0.1:41718)"]
        PROOF -->|inject_crash_rca| BRIDGE
        MAP -->|inject_vad_snapshot| BRIDGE
        VERDICT -->|inject_etw_timeline| BRIDGE
        BRIDGE -->|Authenticated JSON-RPC| SCRIPT["BintraLiveBridgeService.py (Ghidra Client)"]
        SCRIPT -->|currentProgram.startTransaction| GHIDRA_DB["Ghidra Program Database (Plate Comments & Bookmarks)"]
    end
```

---

## 2. الأسس النظرية والخوارزمية للمراحل الأربعة

### المرحلة الأولى: فحص وتصنيف الذاكرة الافتراضية والمسح السلبي (`VirtualMemoryInspector`, `ProcessMemoryScanner`)

- **المسار البرمجي:** [`src/windows_intelligence/runtime_telemetry/virtual_memory_inspector.py`](../src/windows_intelligence/runtime_telemetry/virtual_memory_inspector.py)
- **مبدأ الأمان:** وصول سلبي واستعلامي فقط عبر `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` دون أي حقن أو استدعاء `WriteProcessMemory` أو تعديل لسمات الصفحات، مع إلزامية عزل ملف الجلسة داخل مساحة العمل (`--session-file` / `session_id`).
- **خوارزمية المسح الحيزي والتصنيف الفعلي:**
  - الكشف الديناميكي عن معمارية العملية المستهدفة (WOW64 عبر `IsWow64Process2` أو بنية النظام الأصلي) قبل الاستعلام عبر `VirtualQueryEx` ابتداءً من العنوان `0x0` وحتى السقف المناسب:
    $$V_{\max} = 0x00007FFFFFFFFFFF \quad (\text{x86-64}), \qquad V_{\max} = 0x7FFFFFFF \quad (\text{x86-32 / WOW64})$$
  - تحليل جدول أقسام PE الفعلي في الذاكرة/القرص لتسمية أقسام `MEM_IMAGE` (`.text`, `.rdata`, `.data`, `.rsrc`) وفق عناوين RVA الحقيقية لا التخمين بالصلاحيات فقط، وتمييز مكدس الخيوط الحقيقي (`STACK`) بالاعتماد على صفحات الحراسة (`PAGE_GUARD`) والترابط الحيزي بدلاً من خلطه بكتل الكومة (`HEAP`).
  - المسح الكمي للقيم (First Scan / Next Scan بمختلف الأنواع `int32`/`int64`/`float`/`double`/`bytes`/`string`)، وتعقب مسارات المؤشرات متعددة المستويات (`pointer_scan`)، واستنتاج بنى البيانات (`dissect_struct`) على القراءة المقيدة بالمهلة (`PROCESS_VM_READ`).
- **تدقيق سياسة $W \oplus X$ (Write XOR Execute):**
  - رصد أي صفحة ذاكرة تجمع بين الكتابة والتنفيذ (`PAGE_EXECUTE_READWRITE` أو `PAGE_EXECUTE_WRITECOPY`).
- **الفحص الفارق بين لقطتين (`diff_snapshots`):**
  - مقارنة اللقطات حيزياً مع تتبع تغيّر الحجم والنوع والحالة والصلاحيات وحساب صافي التغير $\Delta \text{Commit}$.

---

### المرحلة الثانية: محرك التحليل الجنائي المؤتمت للانهيارات (`CrashRootCauseAnalyzer`)

- **المسار البرمجي:** [`src/windows_intelligence/runtime_telemetry/crash_rca_engine.py`](../src/windows_intelligence/runtime_telemetry/crash_rca_engine.py)
- **تكامل السجلات، تطبيع الحقول، وفحص VAD:**
  - ترقية [`minidump_parser.py`](../src/windows_intelligence/runtime_telemetry/minidump_parser.py) لاستخراج سجلات x64 الستة عشر، وتطبيع حقلي `operation` و `access_type` (`READ` / `WRITE` / `EXECUTE`) حتى لا تُفقد نوعية الوصول أثناء تمرير مخرجات `.dmp` الحقيقية إلى محرك RCA.
  - الاستعلام الفعلي من `VirtualMemoryInspector` داخل مسار التحليل للتحقق مما إذا كان عنوان الوصول يقع ضمن منطقة كومة أو مكدس أو ملف ذاكرة صالحة أو خارج النطاقات المخصصة.
- **التحليل الإرشادي للمؤشر الفارغ وتفكيك التعليمات:**
  - تفكيك نافذة التعليمات المحيطة بالعطل بواسطة Capstone مع التحقق من محاذاة حدود التعليمة المسببة ومحدوديته الحالية على معمارية `x86`/`x64`.
  - التحقق من المعادلة $\mathtt{TargetAddr} = \mathtt{Reg}_{\mathrm{culprit}} + \mathtt{Displacement}$ وعند مطابقتها مع $\mathtt{Reg}_{\mathrm{culprit}} = 0x0$ يرفع المحرك التصنيف إلى `NULL_POINTER_DEREFERENCE` بمستوى ثقة مرتفع مدعوم بالأدلة (دون ادعاء إثبات رياضي مطلق في غياب سياق التعليمات الكامل).
- **اكتشاف أنماط تسميم الذاكرة (Poison Patterns & UAF):**
  - كشف أنماط تخصيص المترجمات وذاكرة ويندوز المهيأة أو المحررة:
    - `0xDDDDDDDDDDDDDDDD`: كتلة محررة في MSVC Debug CRT (`MSVC_DEAD_FREED_HEAP_BLOCK`).
    - `0xCCCCCCCCCCCCCCCC`: متغير مكدس غير مهيأ (`MSVC_UNINITIALIZED_STACK_VARIABLE`).
    - `0xFEEEFEEEFEEEFEEE`: كتلة محررة في NT Heap.
    - `0xBAADF00DBAADF00D`: كتلة غير مهيأة في NT Heap.
- **توليد التوجيهات البرمجية للمطور (Remediation Advice):**
  - اقتراح فحص دفاعي محدد باسم السجل وموضع الدالة المتأثرة.

---

### المرحلة الثالثة: الالتقاط الهجين للأحداث والسببية الزمنية (`EtwLiveCaptureSession`, `EtwTimelineCorrelator`)

- **المسار البرمجي:** [`src/windows_intelligence/runtime_telemetry/etw_capture_engine.py`](../src/windows_intelligence/runtime_telemetry/etw_capture_engine.py)
- **استهلاك ETW الأصلي والمسار الهجين (Hybrid Native + Non-Elevated Fallbacks):**
  - استدعاء `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace` عبر Win32 `advapi32.dll` لقراءة أحداث Kernel/Image Load/VirtualAlloc/Free الحقيقية مع احترام ملكية الجلسات وعدم إيقاف جلسات خارجية لم ينشئها المحرك.
  - تصنيف الأحداث وتصدير حقلي التتبع **`event_sources`** و **`has_native_etw_events`** لإعلان المصدر الحقيقي لكل حدث (مثل `IMAGE_LOAD`, `VIRTUAL_FREE`, `APPLICATION_ERROR`, `WER_REPORT`, `APPLICATION_HANG`, `KERNEL_POWER_OR_BUGCHECK`, `RESTART_MANAGER_LOCK`) وتقارير الارتباط مثل `GRAPHICS_TDR_DEVICE_REMOVAL`.
- **التخزين الدائري والسببية الزمنية:**
  - الاحتفاظ بأحدث $N$ حدثاً في مخزن دائري محدود في الذاكرة مع التصفية بحسب معرف العملية (PID) والتسلسل الزمني قبل الانهيار (مثل `VIRTUAL_FREE` أو `IMAGE_LOAD` المتأخر خلال $\Delta t \le 500\,\text{ms}$).
- **المرونة في الجلسات غير المرفوعة (Non-Elevated Windows Fallbacks):**
  - نظراً لاشتراط جلسات Kernel ETW الحية صلاحيات **Administrator** أو عضوية مجموعة **Performance Log Users**، ينتقل المحرك تلقائياً دون استثناء في الجلسات الاعتيادية إلى التقاط لقطات الوحدات عبر `CreateToolhelp32Snapshot` وقراءة قنوات `WEVTAPI` (`Application`, `System`, `WER`) مع تمييز ذلك صراحة في النتائج عبر `has_native_etw_events: false`.

---

### المرحلة الرابعة: جسر الاتصال المحلي القائم على الطابور مع Ghidra (`GhidraLiveBridgeServer`, `BintraLiveBridgeService.py`)

- **المسار البرمجي:** [`src/ghidra_live_bridge.py`](../src/ghidra_live_bridge.py) و [`ghidra_scripts/BintraLiveBridgeService.py`](../ghidra_scripts/BintraLiveBridgeService.py)
- **معمارية الطابور والاستطلاع المؤقت (`Queued-Poll JSON-RPC 2.0`):**
  - خادم HTTP متعدد الخيوط (`ThreadingMixIn`) يستمع حصراً على عنوان الحلقة المحلية `127.0.0.1:41718`.
  - يضع المحلل طلبات التحليل في طابور آمن خيطياً، بينما يقوم السكربت داخل غيدرا (`BintraLiveBridgeService.py`, متوافق مع Jython 2.7 و PyGhidra 3.x) بالاستطلاع كل **`1.0s`** وتطبيق المعاملات على `currentProgram` داخل خيط غيدرا.
  - فرض توثيق الرمز السري على كافة مسارات التعديل (`AUTH_REQUIRED` / `-32001`)، وإدارة ملف علامة الاكتشاف المؤقت ضمن صلاحية **`cap.tempdir.marker.write`** (مع إمكانية تعطيله كلياً عبر `--no-temp-marker` أو `publish_temp_marker=false`).
  - تطبيع صريح بين الإزاحة النسبية `rva` والعنوان الافتراضي المطلق `va` وفق `Image Base` المفتوحة في غيدرا لمنع إزاحة التعليقات والعلامات عند إعادة تمركز ASLR.
- **تطبيق التعديلات داخل معاملات قاعدة البيانات (`Database Transactions`):**
  - تنفيذ الإضافات (Plate Comments، وعلامات `BINTRA_CRASH_FAULT`، وملاحظات VAD/ETW، وهياكل C في `DataTypeManager`، وإعادة التسمية) عبر `currentProgram.startTransaction(...)` ككتابات صريحة في قاعدة بيانات غيدرا دون المساس بالملف التنفيذي الأصلي.

---

## 3. مصفوفة أوامر CLI وأدوات MCP المضافة

| الأداة في واجهة CLI | اسم أداة خادم MCP | رقم الأداة | المرحلة | الوظيفة الأساسية |
|---|---|---|---|---|
| `bintra vad-inspect` | `bintra_vad_inspect` | **23** | Phase 1 | مسح الذاكرة الافتراضية، تصنيف أقسام PE والـ STACK/HEAP، تدقيق $W \oplus X$، والفارق الحيزي. |
| `bintra mem-scan` | `bintra_memory_scan` | **24** | Phase 1.5 | قراءة الذاكرة الحية عبر `PROCESS_VM_READ`، والبحث الأولي واللاحق (`first`/`next`) داخل جلسات معزولة. |
| `bintra ptr-scan` | `bintra_pointer_scan` | **25** | Phase 1.5 | استكشاف سلاسل المؤشرات متعددة المستويات حتى العناوين الثابتة للوحدات (`Base+Offsets`). |
| `bintra struct-dissect` | `bintra_struct_dissect` | **26** | Phase 1.5 | تشريح كتل الذاكرة الحية تلقائياً وتوليد تعريفات هياكل C قابلة للحقن في غيدرا. |
| `bintra crash-rca` | `bintra_crash_rca` | **27** | Phase 2 | تحليل ملفات MiniDump، ربط فحص VAD، تفكيك نافذة الانهيار، وإرجاع فرضيات السبب الجذري. |
| `bintra etw-capture` | `bintra_etw_capture` | **28** | Phase 3 | تشغيل التقاط ETW الهجين (`OpenTraceW` + بديل `WEVTAPI`/Toolhelp32) والارتباط الزمني السببي. |
| `bintra ghidra-bridge` | `bintra_ghidra_live_bridge` | **29** | Phase 4 | تشغيل خادم JSON-RPC الموثق على الحلقة المحلية مع دعم `--daemon` و `--no-temp-marker`. |

> [!NOTE]
> يبلغ إجمالي عدد أدوات خادم MCP الآن **34 أداة متخصصة**، جميعها تخضع لوساطة مرجع الأمان `ExecutionGuard` والتحقق الصارم من المخطط (`_validate_tool_arguments`) بنموذج الفشل المغلق (Fail-Closed).

---

## 4. نتائج التدقيق والاختبارات الشاملة (Verification Matrix)

تم التحقق من كافة المكونات عبر حزمة الاختبارات المؤتمتة الكاملة على ويندوز (Python 3.12) بنجاح تام (`0 FAIL`, `0 SKIP`):

```text
======================================================================
Bintra Test Suites Verification Summary:
- test_suite.py (Core Binary & Neural Engines):         123 Tests  [PASS]
- test_security_remediation.py (MCP Guard & Schema):     16 Tests  [PASS]
- test_audit_remediations.py (Audit, CLI, Bridge & Docs): 10 Tests [PASS]
- test_virtual_memory_inspector.py (Phase 1 VAD & Scan):  14 Tests [PASS]
- test_etw_capture_engine.py (Phase 3 Hybrid ETW):        13 Tests [PASS]
- test_ghidra_live_bridge.py (Phase 4 Ghidra Bridge):     14 Tests [PASS]
- test_crash_rca_engine.py (Phase 2 Crash RCA):            4 Tests [PASS]
- test_runtime_telemetry_pipeline.py (Phase 5 E2E):        1 Test  [PASS]
----------------------------------------------------------------------
TOTAL VERIFIED TESTS:                                    195 Tests [PASS]
======================================================================
```

---

## 5. ميثاق الأمان والحياد الهندسي (Strict Security Invariants)

1. **حظر الكتابة على ذاكرة العمليات:** يُمنع منعاً باتاً استدعاء `WriteProcessMemory` أو `VirtualProtectEx` على العمليات الحية؛ يقتصر المسح على `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` فقط.
2. **غياب كود الحقن والتعديل:** المحرك خالٍ تماماً من حقن DLLs أو توليد Shellcode أو برامج تشغيل النواة المخصصة.
3. **العزل المحلي والتوثيق:** خادم غيدرا يرتبط بـ `127.0.0.1` فقط، ويشترط رمز توثيق فريداً (`AUTH_REQUIRED`) للكتابة في قاعدة بيانات غيدرا، ويُبلغ عن صلاحية علامة الدليل المؤقت `cap.tempdir.marker.write`.
4. **ثبات الملفات المستهدفة وسجلات التدقيق:** أوامر الترقيع والتحديث (`patch`, `patch-binary`, `patch-weights`, `update --yes`) تفرض تهيئة `AuditLogger` بنمط الفشل المغلق (`AUDIT_INIT_FAILED`)، بينما تفصح أوامر القراءة عن أي تدهور عبر `"audit_degraded": true`.

---

## 6. القيود المعروفة وضمانات الأمانة الهندسية (Known Limitations & Integrity Guarantees)

- **صلاحيات ETW الحية على ويندوز:** يتطلب استهلاك مزودات النواة الفعلي عبر `OpenTraceW` و `ProcessTrace` صلاحيات إدارية (Administrator أو Performance Log Users)؛ في الجلسات غير المرفوعة، يتحول المحرك تلقائياً إلى `WEVTAPI` و `CreateToolhelp32Snapshot` ويوثق ذلك صراحة عبر `has_native_etw_events: false` و `event_sources` بدلاً من الادعاء بالتقاط نواة حي.
- **محدودية تفكيك التعليمات في Crash RCA:** تفكيك نافذة `-32/+48` بايت حول تعليمة العطل يدعم حالياً معمارية `x86`/`x64` عبر Capstone، وقد لا يصادف بداية التعليمة المثلى قبل العطل إذا سبقته تعليمات متغيرة الطول غير محاذاة، لذا تُعرض النتائج كتشخيص مدعوم بالأدلة لا كبرهان حتمي مطلق.
- **عزل مسارات المسح الذاكري:** تتطلب عمليات مسح القيم (`mem-scan`, `bintra_memory_scan`) حفظ الجلسات حصراً داخل مساحة العمل عبر `ExecutionGuard`؛ أي مسار جلسة خارج النطاق يُرفض تلقائياً برمز `OutOfScopeError`.
- **طبيعة جسر Ghidra غير المتزامنة:** يستخدم الجسر آلية وضع الطلبات في طابور مع استطلاع دوري من داخل غيدرا كل `1.0s`؛ قد يلاحظ استغراقاً بحدود ثانية واحدة قبل ظهور التعليقات أو الهياكل داخل `CodeBrowser`.

### Offline MiniDump Streams & Hardware Correlation
- `MiniDumpParser` extracts `MemoryListStream` (Stream 5), `Memory64ListStream` (Stream 9), `MemoryInfoListStream` (Stream 16), `VS_FIXEDFILEINFO`, and CodeView RSDS/NB10 PDB metadata (`CvRecord`), supporting $O(\log N)$ offline memory reads via `MiniDumpParser.read_memory_from_dump()`.
- `CausalitySynthesizer` is directly exposed on the CLI via `bintra evidence-graph --target <path> --format json|mermaid`.
