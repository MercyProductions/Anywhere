# Aegis Anywhere Detection Monitor

`AnyWhere.exe` is now a console detection monitor. Run the x64 build as administrator so it can query protected process metadata and inspect mapped memory more reliably.

## What It Detects

- Process execution and exit events through WMI process trace events.
- Security, Sysmon, PowerShell, and Service Control Manager event-log telemetry when those logs/providers are enabled.
- Files created, deleted, renamed, and high-signal modifications in Downloads, Desktop, Documents, temp folders, browser cache/profile folders, Startup folders, and scheduled-task folders.
- Likely downloads by combining file location with Mark-of-the-Web (`Zone.Identifier`) alternate data streams.
- High-value registry key and value changes in common persistence and system configuration locations.
- Files mapped into process memory by scanning committed `MEM_IMAGE` and `MEM_MAPPED` regions with `VirtualQueryEx` and `GetMappedFileName`.
- Hidden kernel artifact indicators through SCM/module comparison, driver-file staging detection, suspicious device-handle visibility, and suspicious vulnerable-driver-loader process indicators.
- Transient driver mapping detection for short-lived `.sys` files in Temp, AppData, Downloads, Desktop, ProgramData, Windows temp, driver staging folders, and service-related paths, including evidence preservation, signer/hash/entropy/PE metadata, and mapper-chain correlation.
- Hardware identity cross-validation across WMI, registry, physical-drive IOCTLs, volume/mounted-device records, IP Helper adapter data, firmware tables, DXGI, TPM, monitor EDID identity, and device-stack/filter inventory.
- Hardware identity integrity monitoring focused on HWID-spoofing behavior, including first-seen and last-seen baselines for SMBIOS, BIOS, motherboard, UUID, disk, volume, GPU, MAC, TPM, monitor, and device-stack identity data.
- HWID spoofer profile detection that classifies correlated identity drift into registry-only, driver-backed, network/MAC, disk/volume, SMBIOS/firmware, VM/hypervisor-assisted, and temporary-session spoofing patterns.
- Pre-launch and post-launch identity auditing for protected games and anti-cheat processes. Each launch creates a `HWID-LAUNCH-*` case, captures launch/runtime/exit identity snapshots, scans the pre-launch activity window, and scores temporary spoofing sessions.
- Hardware-change attribution that links identity changes to likely process, driver/service, registry-key, or device-event causes using a 15-minute lookback window and confidence-scored evidence.
- Spoofer cleanup and trace detection that flags identity reverts, short-lived EXE/DLL/SYS/script/config staging files, service cleanup, event-log clearing, adapter toggles, self-delete patterns, and trace-wiping indicators after protected sessions.
- Target process interaction detection for protected/game processes, including visible process handles, suspicious mapped modules, private executable memory, RWX regions, private PE headers, and thread starts outside known mapped module ranges.
- Kernel communication surface detection for newly appearing DOS device names, visible device/section/named-pipe/ALPC handles, protected target handles, suspicious shared sections, and controller-to-game communication chains.
- Trusted process abuse detection for Discord, Steam, NVIDIA overlays, OBS, and browser/GPU processes. It flags suspicious private executable memory, RWX/private PE indicators, unsigned or suspicious mapped images, thread starts outside known modules, kernel/shared-memory channels, and unusual protected-game interaction by trusted apps.
- LOLBIN and native Windows abuse detection for PowerShell, rundll32, regsvr32, mshta, script hosts, installutil, schtasks, sc.exe, reg.exe, pnputil, fltmc, netsh, wevtutil, bcdedit, certutil, bitsadmin, and wmic. It correlates native tool use with driver/service control, identity changes, transient files, telemetry tamper, cleanup behavior, and localhost/controller channels.
- Active Capture mode for High/Critical cases. It builds an evidence-only bundle with process tree, modules, mapped-memory metadata, suspicious memory-region metadata, open handles, registry snapshots, preserved files, event-log excerpts, `timeline.json`, and `summary.txt`.
- Defensive integrity and anti-tamper monitoring for AnyWhere itself, including self-hash drift, suspicious handles to the monitor, suspended/self thread health, log/evidence folder tampering, telemetry collector failures, event-log/audit/Sysmon/Defender/PowerShell/Code Integrity tamper signals, and anti-evasion process heuristics.
- Behavioral profiling and fingerprinting that tags events/cases, builds chain fingerprints, scores rule profiles, clusters artifacts, compares new cases to previous behavioral fingerprints, and writes readable behavior narratives.
- A local reputation and intelligence layer that records hashes, paths, filenames, signers, certificate thumbprints, device names, section/shared-memory names, service names, registry keys, command-line patterns, detection profiles, and case fingerprints across repeated cases.
- Session reconstruction and replay that opens suspicious protected-game sessions, classifies preparation/loader/driver-mapping/spoofing/target-interaction/cleanup phases, writes ordered timelines and event graphs, and stores reusable session fingerprints.
- Real-time detection engine with configurable profiles, chained-event rules, confidence escalation, suppression of low-value known-good noise, burst anomaly detection, and scored detections across driver, loader, spoofer, memory, trusted-process, game-interaction, telemetry-tamper, and cleanup evidence.
- SQLite-backed evidence database for indexed timelines, cases, event details, artifact links, case notes, case tags, historical replay, and cross-case searching.
- Live investigation UI with case list, session timeline, process view, memory anomaly view, driver activity view, hardware identity diff view, communication surface view, evidence browser, case status changes, tags, and analyst notes.
- Baseline learning for trusted-state awareness. It learns repeated low-risk trusted signers, stable process behavior, and trusted paths, then reports drift when a known trusted entity later appears in high-risk target, memory, driver, identity, communication, cleanup, or telemetry-tamper context.

## Event-Log Signals

The monitor subscribes to these high-value event streams:

- Security: `4688`, `4689`, `4657`, `4663`, `4670`, `4697`, `4719`, `1102`.
- Sysmon: `1`, `2`, `3`, `6`, `7`, `10`, `11`, `12`, `13`, `14`, `15`, `22`, `23`, `25`, `26`.
- PowerShell Operational: `4103`, `4104`.
- Code Integrity Operational: selected policy, signing, and blocking/audit events.
- System: `7000`, `7009`, `7011`, `7035`, `7036`, `7045`.

Security object-access and registry events require Windows audit policy to be enabled. Sysmon events require Sysmon to be installed and configured.

Use the included setup helper to preview or apply the recommended local audit settings:

```powershell
.\Tools\Enable-AegisTelemetry.ps1
.\Tools\Enable-AegisTelemetry.ps1 -Apply
```

Run the `-Apply` command from an elevated PowerShell session.

## Output

Logs are written next to the executable under:

```text
Aegis Logs\
```

Each run creates:

- `aegis-events-*.log` for readable text.
- `aegis-events-*.jsonl` for structured event ingestion.
- `aegis-events-*.chain.jsonl` for the rolling hash chain over structured events.
- `Evidence\` copies of downloaded or internet-marked executables when they are observed running or being downloaded.
- `Hardware Identity Integrity\Snapshots\` and `Hardware Identity Integrity\Reports\` for before/after HWID snapshots, baseline diffs, revert/runtime-change evidence, hardware-change attribution, spoofer cleanup traces, and correlated driver/service/process timelines.
- `Hardware Identity Integrity\Launch Sessions\HWID-LAUNCH-*` for protected-process launch audits, including pre-launch diff, runtime diff, post-launch diff, cleanup phase, session timeline, related artifacts, confidence score, and suspected spoofer profile.
- `Transient Driver Mapping\Cases\TDRV-*` reports for short-lived `.sys` staging chains, with preserved evidence copy paths, PE/import metadata, entropy, signer trust, related loader/HWID/kernel/game/cleanup signals, and kernel follow-up requests.
- `Trusted Process Abuse Cases\TPA-*` reports for trusted-app memory/module/IPC/target-access abuse chains.
- `Native Abuse Cases\NATIVE-*` reports for LOLBIN/native Windows tool abuse, suspicious localhost controllers, and correlated native-tool timelines.
- `Active Capture Cases\ACAP-*` bundles for high-confidence correlated cases, with `case-integrity-manifest.json`.
- `Behavioral Profiles\Cases\BHV-*` profiles, narratives, and fingerprint records for recurring behavior analysis.
- `Reputation\reputation-store.tsv` for local artifact classification, previous-case links, import/export intelligence, and manual confirmation state.
- `Session Replay\Sessions\SESSION-*` replay folders with `session-replay.json`, `event-graph.json`, `session-summary.txt`, confidence escalation history, involved artifacts, and `session-fingerprints.jsonl`.
- `Detection Engine Cases\DCASE-*` reports for real-time rule matches, confidence escalations, anomaly detections, matched timeline evidence, involved artifacts, and scored case summaries.
- `AegisEvidence.db` SQLite database with indexed event, case, artifact, case-note, case-tag, and artifact-link tables for live UI and historical investigation.
- `Baseline Learning\trusted-state-baseline.tsv` for adaptive trusted signer, process behavior, and trusted path baseline records.

## Useful Switches

```powershell
.\AnyWhere.exe --map-scan-seconds=10
.\AnyWhere.exe --kernel-scan-seconds=30
.\AnyWhere.exe --identity-scan-seconds=60
.\AnyWhere.exe --disable-hwid-integrity
.\AnyWhere.exe --hwid-integrity-scan-seconds=60
.\AnyWhere.exe --protected-process=cod.exe
.\AnyWhere.exe --protected-process=*-Win64-Shipping.exe
.\AnyWhere.exe --target-scan-seconds=5
.\AnyWhere.exe --kernel-comm-scan-seconds=5
.\AnyWhere.exe --disable-defensive-integrity
.\AnyWhere.exe --defensive-integrity-scan-seconds=15
.\AnyWhere.exe --disable-behavioral-profiling
.\AnyWhere.exe --behavior-window-minutes=10
.\AnyWhere.exe --behavior-similarity-threshold=0.58
.\AnyWhere.exe --disable-reputation
.\AnyWhere.exe --reputation-import=C:\Intel\known-bad-hashes.txt
.\AnyWhere.exe --reputation-export=C:\Intel\aegis-reputation.tsv
.\AnyWhere.exe "--reputation-mark=sha256|confirmed_loader|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|manual case review"
.\AnyWhere.exe "--reputation-mark=CASE-2026-05-19-004|device_name|confirmed_mapper|\Device\ExampleDevice|confirmed mapper controller"
.\AnyWhere.exe --disable-active-capture
.\AnyWhere.exe --active-capture-cooldown-seconds=180
.\AnyWhere.exe --active-capture-event-log-minutes=15
.\AnyWhere.exe --active-capture-max-memory-regions=256
.\AnyWhere.exe --archive-cases
.\AnyWhere.exe --evidence-mirror=D:\AegisEvidenceMirror
.\AnyWhere.exe --emit-initial-mapped-files
.\AnyWhere.exe --watch-all-fixed-drives
.\AnyWhere.exe --ui
.\AnyWhere.exe --gui
.\AnyWhere.exe --console
.\AnyWhere.exe --auto-load-kernel-sensor
.\AnyWhere.exe "--kernel-sensor-driver=C:\AegisDrivers\AegisKernelSensor.sys" --kernel-sensor-service=AegisKernelSensor
.\AnyWhere.exe --detection-profile=balanced
.\AnyWhere.exe --detection-profile=aggressive
.\AnyWhere.exe --detection-profile=silent-telemetry
.\AnyWhere.exe --detection-profile=anti-spoofer-focus
.\AnyWhere.exe --detection-profile=anti-hidden-driver-focus
.\AnyWhere.exe --detection-profile=development-testing
.\AnyWhere.exe --database=C:\AegisEvidence\AegisEvidence.db
.\AnyWhere.exe "--case-status=DCASE-20260519-120000-abcd1234|confirmed|reviewed by analyst"
.\AnyWhere.exe "--case-note=DCASE-20260519-120000-abcd1234|Loader and driver activity line up with game launch."
.\AnyWhere.exe "--case-tag=DCASE-20260519-120000-abcd1234|confirmed_mapper"
.\AnyWhere.exe "--export-case=DCASE-20260519-120000-abcd1234" --database=C:\AegisEvidence\AegisEvidence.db --export-output=C:\AegisExports
.\AnyWhere.exe --platform-self-test
.\AnyWhere.exe "--replay=C:\Aegis Logs\aegis-events-20260519-190617.jsonl"
.\AnyWhere.exe "--replay=C:\Aegis Logs" --replay-output=C:\AegisReplay --detection-profile=development-testing
.\AnyWhere.exe "--replay=C:\Aegis Logs" --replay-expect=C:\AegisReplay\expected.json
.\AnyWhere.exe --quiet
.\AnyWhere.exe --max-hash-mb=250
.\AnyWhere.exe --max-device-handles=2000
.\AnyWhere.exe --max-process-handles=50000
.\AnyWhere.exe --max-kernel-comm-handles=50000
.\AnyWhere.exe --max-active-capture-handles=50000
.\AnyWhere.exe --max-self-handle-scan=50000
```

- `--map-scan-seconds=N` changes how often memory mappings are scanned. Minimum is 3 seconds.
- `--kernel-scan-seconds=N` changes how often hidden-kernel artifact inventory checks run. Minimum is 10 seconds.
- `--identity-scan-seconds=N` changes how often hardware identity cross-validation runs. Minimum is 15 seconds.
- `--disable-hwid-integrity` disables HWID integrity drift, revert, device-stack, TPM, monitor, and spoofing-behavior correlation checks.
- `--hwid-integrity-scan-seconds=N` changes how often HWID integrity snapshots run. Minimum is 15 seconds.
- `--protected-process=name.exe` adds a protected game/process name that triggers launch/runtime/exit identity snapshots. Repeat values can be comma-separated.
- `--target-scan-seconds=N` changes how often protected target interaction checks run. Minimum is 2 seconds.
- `--kernel-comm-scan-seconds=N` changes how often kernel communication surfaces are scanned. Minimum is 2 seconds.
- `--disable-defensive-integrity` disables self-integrity and anti-tamper monitoring.
- `--defensive-integrity-scan-seconds=N` changes how often self-integrity, handle-to-self, and telemetry health checks run. Minimum is 5 seconds.
- `--disable-behavioral-profiling` disables behavioral tags, fingerprints, profile scoring, and prior-case similarity comparisons.
- `--behavior-window-minutes=N` controls how long events can accumulate into a behavioral case. Minimum is 1 minute.
- `--behavior-similarity-threshold=N` controls prior-case similarity alerting from `0.0` to `1.0`.
- `--disable-reputation` disables runtime reputation observation while leaving other telemetry intact.
- `--reputation-import=PATH` imports a local intelligence file. It accepts Aegis TSV exports, `type|category|value|notes` rows, `category|type|value|notes` rows, or plain SHA-256 hash lists as known-bad hash intelligence.
- `--reputation-export=PATH` writes the current local reputation database for backup or transfer.
- `--reputation-mark=...` manually classifies an artifact. Use `type|category|value|note` or `case_id|type|category|value|note`.
- `--disable-active-capture` keeps correlation alerts enabled but prevents automatic deep evidence bundles.
- `--active-capture-cooldown-seconds=N` controls how often the same trigger/case can produce a bundle. Minimum is 30 seconds.
- `--active-capture-event-log-minutes=N` controls the lookback window for event-log excerpts.
- `--active-capture-max-memory-regions=N` caps suspicious memory-region metadata rows per involved process.
- `--archive-cases` creates optional zip archives for Active Capture case folders after manifests are written.
- `--evidence-mirror=PATH` duplicates Active Capture case folders to a secondary storage location.
- `--emit-initial-mapped-files` logs every mapped file found during the first scan. Without it, the first scan is a baseline and only new mappings are emitted.
- `--watch-all-fixed-drives` recursively watches every fixed drive. This is noisy but broader.
- `--ui` or `--gui` sets the global GUI mode flag at startup and opens the investigation interface while the collectors continue running.
- `--console` clears the global GUI mode flag and keeps the process in console monitoring mode.
- `--auto-load-kernel-sensor` attempts to create/update/start a demand-start kernel-driver service through the Windows Service Control Manager before live monitoring begins. This uses the standard signed or test-signed driver path only; there is no mapper, vulnerable-driver, unsigned-driver, or signature-bypass fallback.
- `--kernel-sensor-driver=PATH` sets the `.sys` file to load and also enables kernel-sensor auto-load. Without it, Aegis looks for `AegisKernelSensor.sys` or `AegisDriver2.sys` next to the executable and in known development build output paths.
- `--kernel-sensor-service=NAME` sets the service name used for the kernel sensor. If omitted, Aegis uses the driver filename without `.sys`.
- `--detection-profile=NAME` selects `balanced`, `aggressive`, `silent-telemetry`, `anti-spoofer-focus`, `anti-hidden-driver-focus`, or `development-testing`.
- `--database=PATH` stores the SQLite evidence database at a specific path instead of the run log folder.
- `--disable-evidence-db` disables SQLite storage and the live UI database backend.
- `--case-status=CASE|STATUS|NOTE` updates a case classification. Supported statuses are free-form, but the UI offers `open`, `investigating`, `confirmed`, `false_positive`, `trusted`, and `closed`.
- `--case-note=CASE|NOTE` appends an analyst note to a case.
- `--case-tag=CASE|TAG` adds a tag to a case.
- `--export-case=CASE` creates a portable reviewer bundle from the SQLite evidence database without starting live collectors. The bundle includes `summary.html`, `case.json`, `timeline.csv`, `case-events.jsonl`, artifact/detail/note/tag CSVs, mirrored Aegis case evidence when available, and `case-integrity-manifest.json`.
- `--export-output=PATH` writes case exports to a folder, or to a specific `.zip` path when the value ends with `.zip`. Without it, exports go under `Aegis Logs\Case Exports\`.
- `--platform-self-test` initializes the SQLite provider, creates a self-test database, inserts a test event, and exits.
- `--replay=PATH` or `--replay-input=PATH` replays one JSONL file, a wildcard, or a directory of saved Aegis JSONL logs through the offline detection replay harness. It starts event-driven analysis only: evidence database, real-time rules, baseline learning, behavioral profiles, reputation, and session replay.
- `--replay-output=PATH` writes replay logs, database, generated cases, and `replay-summary.txt` to a specific directory. Without it, replay output goes under `Aegis Logs\Replay\`.
- `--replay-expect=PATH` or `--replay-expectations=PATH` evaluates a golden replay expectation JSON after replay. It writes `replay-expectations.txt`, marks the replay summary as pass/fail, and exits with code `2` when expectations fail.
- `--replay-include-derived` also feeds previously generated DetectionEngine, BehaviorProfile, Reputation, SessionReplay, ActiveCapture, Monitor, and EvidenceDatabase events back into replay. By default these are skipped so detections are regenerated from source telemetry.
- `--replay-rebase-timestamps` maps source event timestamps onto the current replay run while preserving their relative offsets. Without it, source timestamps are preserved.
- `--quiet` keeps the console focused on medium and higher severity events while still writing all events to disk.
- `--max-hash-mb=N` controls the largest file that will be SHA-256 hashed.
- `--max-device-handles=N` caps each visible device-handle scan. Use `0` to disable user-mode handle inspection.
- `--max-process-handles=N` caps each visible process-handle scan for target interaction detection. Use `0` to disable process-handle inspection.
- `--max-kernel-comm-handles=N` caps each visible object-handle scan for kernel communication surface detection. Use `0` to disable this handle inspection pass.
- `--max-active-capture-handles=N` caps the active-capture handle snapshot pass. Use `0` to skip handle snapshots inside bundles.
- `--max-self-handle-scan=N` caps the defensive integrity scan for suspicious process handles to AnyWhere. Use `0` to disable this specific scan.

Example replay expectation file:

```json
{
  "description": "Golden replay for transient driver staging sample",
  "min_files_read": 1,
  "min_replayed_events": 1,
  "max_parse_failures": 0,
  "expected_events": [
    {
      "name": "detection engine fired",
      "category": "DetectionEngine",
      "min_count": 1
    }
  ],
  "expected_cases": [
    {
      "name": "transient driver rule",
      "category": "DetectionEngine",
      "rule_id": "transient_driver_mapper_chain",
      "min_confidence": 0.60,
      "min_count": 1
    }
  ]
}
```

## Limits

This is user-mode detection. It can catch a lot of staging, service/module mismatches, visible device handles, suspicious shared objects, event-log traces, and file-backed mappings, but truly manually mapped hidden kernel code requires a signed or test-signed defensive kernel sensor. See `KERNEL_ASSISTED_DETECTION.md` for the read-only sensor contract.

Transient driver mapping detection emits `TransientDriverMapping/TransientDriverFileAppeared`, `TransientDriverMapping/TransientDriverMappingSuspected`, and `TransientDriverMapping/KernelMemoryFollowUpRequested`. It immediately hashes and copies staged `.sys` files when readable, records signer trust, MOTW, size, entropy, PE metadata, import names, likely parent process context, rename/write/delete activity, and correlates the file with suspicious loaders, vulnerable-driver use, SCM/Code Integrity events, hidden-kernel indicators, device/shared-memory surfaces, protected game access, HWID changes, and cleanup behavior. Kernel-memory follow-up remains read-only and requires a signed defensive kernel sensor for true kernel memory scans.

Active Capture intentionally starts with memory metadata only: base address, size, protection, type, entropy sample, PE-header presence, mapped path, owning process, and thread-start links. It does not dump full process memory and does not kill, block, unload, patch, hide, inject, or bypass anything.

Defensive integrity monitoring is also evidence-only. It reports interference attempts and preserves integrity metadata; it does not protect by fighting the system, patching kernel structures, hooking internals, or blocking other processes.

Behavioral profiles are recognition aids, not static proof. They combine tags such as `manual_map_behavior`, `hidden_driver_pattern`, `vulnerable_driver_loader`, `unsigned_game_access`, `suspicious_device_channel`, `memory_injection_pattern`, `transient_loader_behavior`, `anti_debug_behavior`, `telemetry_tamper_behavior`, `trusted_process_abuse`, `lolbin_native_abuse`, and `local_controller_channel` with chain timing and artifact clusters to help spot repeat patterns. Rule profiles now include trusted-process abuse, LOLBIN/native-loader workflows, and local-controller workflows in addition to mapper, hidden-driver, injector, bootstrap, target-manipulator, and telemetry-tamper profiles.

Reputation records are local investigation intelligence. Categories include `trusted`, `known_good`, `unknown`, `suspicious`, `confirmed_cheat_artifact`, `confirmed_mapper`, `confirmed_loader`, `confirmed_hidden_driver_indicator`, and `false_positive`. Reputation events can recommend raising confidence for repeat or confirmed artifacts, or lowering noise for known-good artifacts, but they do not rewrite or hide the original evidence event.

Hardware identity checks compare independent Windows sources and baseline snapshots, but vendor firmware quality varies. They flag disk serial/model/vendor mismatches, runtime MAC mismatches, locally administered MACs, adapter reset context, SMBIOS/registry/firmware disagreement, randomized-looking firmware serials, GPU/DXGI/device-stack drift, unsigned display drivers, suspicious device filters, and serial changes without a matching real-device change. Treat high-confidence mismatches as investigation leads with supporting evidence, not automatic proof of tampering.

HWID integrity monitoring keeps two local baselines: first-seen identity values and last-seen identity values. It flags changed, newly appeared, missing, rapidly changing, and reverted identifiers, then raises confidence when those changes occur near hidden-driver indicators, vulnerable-driver/mapper behavior, temporary `.sys` files, suspicious service creation/deletion, hardware registry edits, device-object creation, or protected game runtime.

HWID spoofer profile events are emitted as `HardwareIdentityIntegrity/HwidSpooferProfileMatched`. Each profile includes a profile name, confidence score, matched indicators, before/after identity diff, related processes/drivers/services, evidence timeline, and case links. The supported profiles are `registry_only_spoofer`, `driver_backed_spoofer`, `network_mac_spoofer`, `disk_volume_spoofer`, `smbios_firmware_spoofer`, `vm_hypervisor_assisted_spoofer`, and `temporary_session_spoofer`.

Pre/post launch auditing emits `HardwareIdentityIntegrity/PreLaunchIdentityAudit`, `HardwareIdentityIntegrity/RuntimeIdentityDriftObserved`, and `HardwareIdentityIntegrity/LaunchSessionIdentityAuditComplete`. The pre-launch window currently looks back 15 minutes for hardware registry edits, NIC reset indicators, disk/volume changes, service or driver-load activity, suspicious loader execution, vulnerable-driver indicators, mapper behavior, and hidden-kernel indicators. Session scoring rises when identity values change only during protected runtime, revert after exit, or line up with pre-launch loader/driver activity.

Hardware-change attribution emits `HardwareIdentityIntegrity/HardwareChangeAttributed`. Each attribution includes the changed identifier, old value, new value, suspected cause, related process, related driver/service, related registry key, related device event, matched signals, confidence score, and evidence timeline. It correlates identity drift with suspicious/elevated/unsigned process launches, user-writable paths, hardware-control commands, visible device/section handles, loaded-driver/service events, temporary `.sys` files, hardware registry changes, adapter resets, storage resets, PnP re-enumeration, and virtual device appearance/disappearance.

Spoofer cleanup detection emits `HardwareIdentityIntegrity/SpooferCleanupTraceDetected` and adds `spoofer_cleanup_traces` to HWID reports and launch-session reports. It scores cleanup phases when identities revert after protected-process exit or reboot, short-lived staging files disappear, services or service keys are removed after driver-like behavior, event logs or trace stores are cleared, adapters are disabled/re-enabled, temp artifacts are deleted, or machine/NIC/storage/hardware registry values change and later restore. `File/ShortLivedStagingFileDeleted` is emitted for quickly deleted EXE, DLL, SYS, scripts, and temp config artifacts.

Session reconstruction emits `SessionReplay/SessionReconstructed` for completed sessions and `SessionReplay/SessionReplayUpdated` for high-confidence sessions still in progress. The replay JSON contains an ordered event timeline, phase-grouped activity, event graph, involved processes/files/drivers/identifiers, confidence escalation timeline, human-readable summary, and fingerprint features for event order, timing, loader style, cleanup style, spoofing behavior, memory behavior, and communication behavior. SessionEngine is passive and evidence-only.
