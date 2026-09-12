# Restricted Assets — BrainTrustCrypto MoneyPrinterTurbo

**Date:** 2026-08-30
**Status:** UNVERIFIED_RESTRICTED
**Classification:** These assets are present in the repository for upstream compatibility but are **prohibited** for use in any BrainTrustCrypto-generated content.

---

## Classification: UNVERIFIED_RESTRICTED

All files under `resource/songs/` and `resource/fonts/` are classified as **UNVERIFIED_RESTRICTED**. This means:

1. **No provenance.** No source URL, retrieval date, or chain of custody exists for any of these files.
2. **No license documentation.** No license files, attribution notices, or usage rights are included.
3. **Prohibited for BrainTrustCrypto.** These assets must NOT be used in any content generated for BrainTrustCrypto. This includes videos, thumbnails, subtitles, metadata, and any derived works.
4. **Present for upstream compatibility only.** They remain in the repository to avoid breaking upstream MoneyPrinterTurbo functionality and to simplify future upstream syncs.

---

## Restricted Music (`resource/songs/`)

**Count:** 29 MP3 files (`output000.mp3` through `output029.mp3`, with gaps)

**Risk:**
- No source URL or retrieval date for any file
- No license information or artist attribution
- No evidence of royalty-free or Creative Commons status
- Using unlicensed music in published YouTube content risks copyright strikes, Content ID claims, and channel demonetization

**Pilot config enforcement:** `bgm.source = "none"` in `hardening.example.toml` ensures no bundled music is selected.

**Cannot be used until:**
- Each track is replaced with a verified, licensed alternative
- Replacement tracks have full provenance (source URL, retrieval date, license, artist)
- Provenance is recorded in the task-level provenance manifest

---

## Restricted Fonts (`resource/fonts/`)

**Count:** 9 font files

| Font file | License concern |
|---|---|
| `MicrosoftYaHeiBold.ttc` | Microsoft proprietary — redistribution not permitted |
| `MicrosoftYaHeiNormal.ttc` | Microsoft proprietary — redistribution not permitted |
| `STHeitiLight.ttc` | Apple proprietary — redistribution not permitted |
| `STHeitiMedium.ttc` | Apple proprietary — redistribution not permitted |
| `BeVietnamPro-Bold.ttf` | SIL Open Font License — likely OK but needs verification |
| `BeVietnamPro-Medium.ttf` | SIL Open Font License — likely OK but needs verification |
| `Charm-Bold.ttf` | Unknown — needs verification |
| `Charm-Regular.ttf` | Unknown — needs verification |
| `UTM Kabel KT.ttf` | Unknown — needs verification |

**Risk:**
- Microsoft YaHei and STHeiti are proprietary system fonts owned by Microsoft and Apple respectively. Bundling them in a third-party project does not grant redistribution rights.
- Charm and UTM Kabel KT have no identifiable license information.
- BeVietnamPro is likely SIL OFL but requires verification before use.

**Pilot config enforcement:** The pilot configuration does not reference any font files. Subtitle rendering is not active in Phase 1A.

**Cannot be used until:**
- Proprietary fonts (Microsoft, Apple) are replaced with verified open-license alternatives
- Unknown-license fonts are either verified or replaced
- All replacement fonts have documented licenses included alongside the font files

---

## Quarantine Copies

Local quarantine copies exist in `quarantine/songs/` and `quarantine/fonts/` (gitignored). These are preserved as a safety net and are identical to the restored `resource/` copies. They will not be committed to the repository.

---

## Replacement Plan (Future Phase)

- **Music:** Rick will supply licensed tracks or select from a verified royalty-free library. Each track must have a `PROVENANCE.md` entry.
- **Fonts:** Recommended replacements are Inter (SIL OFL 1.1) and Noto Sans (SIL OFL 1.1). Both are free for commercial use with attribution.
