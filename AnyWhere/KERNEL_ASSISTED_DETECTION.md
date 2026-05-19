# Hidden Kernel Artifact Detection

This document defines the defensive-only kernel-assisted checks that `HiddenKernelArtifactDetector` is designed to consume if a signed or test-signed Aegis defensive sensor is added later.

The rule for this sensor is evidence only:

- Do not patch kernel memory.
- Do not unlink, relink, unload, or hide objects.
- Do not inject, map, or execute code.
- Do not bypass platform protections.
- Return observations, hashes, addresses, owning module decisions, and confidence only.

## User-Mode Coverage Already Implemented

`HiddenKernelArtifactDetector` currently performs these user-mode checks:

- Compares SCM `Win32_SystemDriver` services against `EnumDeviceDrivers` loaded-module inventory.
- Flags running kernel-driver services that do not have a matching visible loaded module.
- Flags visible loaded modules that do not have an obvious SCM driver-service match.
- Scans known driver-file locations for recently dropped untrusted `.sys` files.
- Watches driver staging roots for `.sys` create, delete, rename, change, and short-lived staging.
- Flags suspicious vulnerable-driver-loader process indicators.
- Scans visible handles for suspicious device-object names when user-mode handle enumeration allows it.
- Logs that deep kernel-assisted checks are unavailable until a defensive sensor is connected.

## Required Kernel-Assisted Checks

A defensive kernel sensor should report:

- Kernel executable memory ranges outside known loaded-module ranges.
- PE headers found in executable kernel memory outside known modules.
- Differences between `PsLoadedModuleList` and memory-backed executable regions.
- Driver objects or device objects not linked through expected loader/object-manager structures.
- System threads with start addresses outside known module ranges.
- Kernel callbacks whose function pointers point outside known signed module ranges.
- Driver dispatch table entries pointing to unmapped, private, or unknown executable memory.
- Loaded-module list integrity issues.
- Hashes of suspicious executable kernel regions.
- Signature/trust status for the owning module when ownership can be resolved.

## Suggested Evidence Schema

The user-mode monitor should receive read-only observations shaped like:

```json
{
  "category": "KernelAssist",
  "action": "ExecutableRegionOutsideModule",
  "severity": "High",
  "address": "0xFFFFF80000000000",
  "size": 4096,
  "protection": "RX",
  "owner_module": null,
  "nearest_module": "ntoskrnl.exe",
  "sha256": "region hash",
  "has_mz_header": true,
  "has_pe_header": true,
  "thread_id": null,
  "callback_type": null,
  "driver_object": null,
  "device_object": null,
  "notes": "Read-only observation; no remediation attempted."
}
```

## Integration Boundary

The user-mode monitor expects a future defensive sensor to expose a read-only device such as:

```text
\\.\AegisKernelSensor
```

Allowed operations should be inventory/query only, for example:

- `QueryCapabilities`
- `QueryLoadedModuleIntegrity`
- `QueryExecutableKernelRegions`
- `QuerySuspiciousDriverObjects`
- `QuerySuspiciousDeviceObjects`
- `QuerySystemThreadStarts`
- `QueryKernelCallbacks`
- `QueryDispatchTables`

No mutation IOCTLs should exist in this defensive sensor.
