# Quarantined Assets — BrainTrustCrypto MoneyPrinterTurbo

**Date:** 2026-08-30
**Action:** Quarantine (move, not delete)
**Reason:** These assets ship with the upstream repository but have no provenance, license documentation, or source attribution. They cannot be used in BrainTrustCrypto content.

---

## Quarantined Music (`quarantine/songs/`)

**Count:** 29 MP3 files (`output000.mp3` through `output028.mp3`, with gaps)

**Why quarantined:**
- No source URL or retrieval date for any file
- No license information or artist attribution
- No evidence of royalty-free or Creative Commons status
- Using unlicensed music in published YouTube content risks copyright strikes, Content ID claims, and channel demonetization

**Cannot be used until:**
- Each track is replaced with a verified, licensed alternative
- Replacement tracks have full provenance (source URL, retrieval date, license, artist)
- Provenance is recorded in the task-level provenance manifest

---

## Quarantined Fonts (`quarantine/fonts/`)

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

**Why quarantined:**
- Microsoft YaHei and STHeiti are proprietary system fonts owned by Microsoft and Apple respectively. Bundling them in a third-party project does not grant redistribution rights.
- Charm and UTM Kabel KT have no identifiable license information.
- BeVietnamPro is likely SIL OFL but requires verification before use.

**Cannot be used until:**
- Proprietary fonts (Microsoft, Apple) are replaced with verified open-license alternatives
- Unknown-license fonts are either verified or replaced
- All replacement fonts have documented licenses included alongside the font files

---

## Replacement Plan (Future Phase)

- **Music:** Rick will supply licensed tracks or select from a verified royalty-free library. Each track must have a `PROVENANCE.md` entry.
- **Fonts:** Recommended replacements are Inter (SIL OFL 1.1) and Noto Sans (SIL OFL 1.1). Both are free for commercial use with attribution.

---

## Restoration

To restore quarantined assets (e.g., for upstream sync):

```powershell
Move-Item quarantine/songs/* resource/songs/
Move-Item quarantine/fonts/* resource/fonts/
```

**Note:** The `quarantine/` directory is gitignored. These files will not be committed to the repository.
