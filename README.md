# Postmortem — Forensic Analysis Tool

> Automated disk & memory forensics triage in a single Bash script.
> Hand it one piece of evidence; get back a structured report and a packaged archive.

**Unit:** NX212 · **Author:** Alon Agronov (s16) · **Lecturer:** Natalie Erez

---

## What it does

Postmortem takes a single disk image or memory capture and runs a full triage pipeline over it automatically. The only human input is the filename — everything after that (tool installation, file carving, string extraction, memory analysis, reporting, and packaging) runs unattended.

What would otherwise be an hour of manual, error-prone tool-wrangling becomes one command:

```bash
sudo ./postmortem.sh <image_file>
```

---

## Pipeline

The script moves through four stages:

**1. Set up the case** — verifies root privileges, confirms the evidence file exists, checks that every required tool is installed (installing any that are missing), and creates a timestamped output directory so runs never collide.

**2. Recover what's hidden** — four carvers each look for something different:
- **Foremost** — file carving by signature
- **Binwalk** — signature scan + recursive extraction of embedded files
- **Bulk Extractor** — emails, URLs, network captures, and other features
- **Strings** — readable text, filtered for credentials, tokens, and executable references

**3. See what was running** *(memory images only)* — if the evidence is a valid memory capture, Volatility 3 reconstructs the machine's state at capture time: running processes, network connections, and registry hives. If the file isn't a memory image, this stage is skipped cleanly.

**4. Report & package** — counts everything, writes a structured report (findings, counts, runtime), and zips the full results directory into a single archive.

---

## Requirements

- Linux (developed and tested on Kali)
- Root privileges (`sudo`)
- Auto-installed if missing: `foremost`, `binwalk`, `bulk-extractor`, `binutils`
- **Volatility 3** — optional; if absent, memory analysis is skipped. Install via `pipx install volatility3`.

---

## Usage

```bash
# with a filename
sudo ./postmortem.sh evidence.raw

# or run bare and it will prompt
sudo ./postmortem.sh
```

### Output

Results are written to a timestamped directory, `results_<image>_<date>/`:

```
results_.../
├── foremost/          # carved files
├── binwalk/           # extracted files + signature scan
├── bulk_extractor/    # feature files, network captures
├── strings/           # full dump + per-keyword hit files
├── volatility/        # memory analysis output
├── logs/              # per-tool diagnostic logs
└── report/report.txt  # summary report
```

...and the whole directory is zipped alongside it.

---



## Notes & limitations

- **Volatility 3 only.** Chosen deliberately over Volatility 2, which requires manual profile detection and (on modern systems) a difficult Python 2 install. 
- Memory analysis is **Windows-focused**.
- This is a **triage** tool. Its keyword hits and carved files are leads for deeper manual examination, not conclusions.

---
---

*Developed as part of unit NX212.*
