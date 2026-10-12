# Legacy scripts

Superseded by the tooling in [`../scripts/`](../scripts/). Kept because
`hpe-secureboot-audit-v2.sh` and `Check-SecureBoot-OneView.ps1` implement **HPE OneView
SSO discovery**, which the v2 scripts do not yet have — for a OneView-managed estate
that is still the fastest way to enumerate iLO endpoints without distributing iLO
credentials.

## Known inaccuracies — do not rely on these

The facts embedded in these scripts and in `README.cs.md` predate HPE advisory
a00156355en_us rev. 5 (2026-07-02) and Broadcom's revised VM guidance.

| Claim in legacy docs | Correction |
|---|---|
| Gen11 min. ROM `2.42` | Correct for Intel; AMD needs **2.30** |
| Gen12 | Not covered at all — 2023 certificates are active from the factory, key reset **must not** be performed |
| iLO 5 `SecureBootDatabases`: *"only with a sufficiently new ROM"* | **Incorrect.** iLO 5 never exposes `SecureBootDatabases`; introduced in iLO 6 v1.10. `list-ilo5-uefi-certs.py` was removed for this reason |
| Detects `KEK_2023` and `DB_2023` | Four certificates must be checked. `Microsoft Option ROM UEFI CA 2023` is separate from `Microsoft UEFI CA 2023` and is the one most often missing |
| VM guidance | Predates `VMW.NULLPK`, SilentPK, and ESXi 8.0 U3j (build 25429389) |

`README.cs.md` is the original Czech documentation, preserved unchanged for reference.
