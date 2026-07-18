# EntraScope GUI — Options Comparison & Requirements Reference

## At a Glance

| | Electron | Python + CustomTkinter | PowerShell + WPF | Tauri |
|---|---|---|---|---|
| **Visual Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Setup Effort** | Medium | Low–Medium | Lowest | High |
| **New Runtimes Needed** | Node.js 20 | Python 3.11 | None | Rust + Node.js |
| **Disk (app + deps)** | ~350 MB dev / ~85 MB dist | ~120 MB venv / ~45 MB exe | ~100 KB | ~200 MB dev / ~5 MB dist |
| **Distributable Size** | ~85 MB | ~45 MB | single .ps1 | ~5 MB |
| **Windows Only?** | No | No | Yes | No |
| **PS Integration** | subprocess pipe | subprocess pipe | in-process direct | subprocess pipe |
| **Live Log Streaming** | ✅ node-pty | ✅ threading | ✅ Dispatcher | ✅ tauri command |
| **In-app Charts** | ✅ chart.js | ⚠️ plotly → browser | ⚠️ WPF DrawingContext | ✅ chart.js |
| **Build for Electron** | npm run build | pyinstaller | n/a | cargo tauri build |
| **Recommended for** | Best polish | Quick to build | Zero dependencies | Smallest binary |

---

## File Locations

```
EntraScope/
└── gui/
    ├── Check-AllRequirements.ps1        ← Run this first to see which option is ready
    │
    ├── electron/
    │   ├── package.json                 ← npm dependencies (run: npm install)
    │   └── REQUIREMENTS.txt            ← Full system requirements reference
    │
    ├── python/
    │   ├── requirements.txt             ← pip dependencies (run: pip install -r requirements.txt)
    │   └── REQUIREMENTS.txt            ← Full system requirements reference
    │
    └── wpf/
        ├── Check-Requirements.ps1       ← WPF-specific prerequisites checker
        └── REQUIREMENTS.txt            ← Full system requirements reference
```

---

## Quick Start — Run the Checker First

```powershell
# Find out which GUI option your system is ready for RIGHT NOW:
pwsh -File .\gui\Check-AllRequirements.ps1
```

This produces a readiness table like:

```
  ✅  WPF          [███░]  3/3 ready   → zero extra installs needed
  ⚠️   Electron     [██░░]  2/3 ready   → install MSBuild C++ tools
  ⚠️   Python       [██░░]  2/4 ready   → pip install -r requirements.txt
  ❌  Tauri        [░░░░]  0/4 ready   → install Rust toolchain
```

---

## Installing Each Option

### Electron (Recommended — Best UI)

```powershell
# Prerequisites
winget install OpenJS.NodeJS.LTS
winget install Microsoft.VisualStudio.2022.BuildTools
# In VS installer: select "Desktop development with C++"

# Install & run
cd EntraScope\gui\electron
npm install
npm run dev

# Build distributable
npm run build
# → dist\EntraScope Setup 1.0.0.exe   (NSIS installer)
# → dist\EntraScope 1.0.0.exe          (portable)
```

**Key packages:**
- `electron` — Chromium + Node.js shell
- `node-pty` — Real PTY for PowerShell output streaming (ANSI colours preserved)
- `xterm` — Terminal emulator widget
- `chart.js` — Security score + phase charts
- `electron-store` — Persist settings between sessions
- `chokidar` — Auto-reload report when scan completes

---

### Python + CustomTkinter

```powershell
# Prerequisites
winget install Python.Python.3.11   # Use winget or python.org — NOT Windows Store

# Install & run
cd EntraScope\gui\python
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py

# Build standalone exe
pip install pyinstaller
pyinstaller --onefile --windowed --name=EntraScope app.py
# → dist\EntraScope.exe  (~45 MB, no Python needed on target)
```

**Key packages:**
- `customtkinter` — Modern dark-mode widgets
- `CTkTable` — Scrollable results grid
- `pywin32` — Real-time PowerShell stdout streaming
- `plotly` — Charts (rendered to browser or webview)
- `jsonschema` — scope.json validation before scan

---

### PowerShell + WPF (Zero new installs)

```powershell
# Prerequisites — already met if you have PS7 on Windows 10/11
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
Install-Module MSAL.PS -Scope CurrentUser   # optional — browser auth

# Verify
pwsh -File .\gui\wpf\Check-Requirements.ps1

# Run
pwsh -STA -File .\gui\wpf\EntraScopeGUI.ps1
```

**What's used:**
- `PresentationFramework` — WPF windows and controls (built-in .NET)
- `System.Xaml` — XAML layout parser (built-in .NET)
- `System.Windows.Forms` — File picker dialogs (built-in .NET)
- `MSAL.PS` — Optional browser-based login

---

### Tauri (Smallest binary — advanced)

```powershell
# Prerequisites
winget install Rustlang.Rustup
rustup install stable
rustup target add x86_64-pc-windows-msvc
winget install OpenJS.NodeJS.LTS

# Install & run
cd EntraScope\gui\tauri
npm install
npm run tauri dev

# Build
npm run tauri build
# → src-tauri\target\release\bundle\msi\EntraScope_1.0.0_x64_en-US.msi  (~5 MB)
```

---

## Decision Guide

**Run Check-AllRequirements.ps1 first.** Then:

- If **WPF shows 3/3** — start there. Zero installs, works immediately.
- If **Node.js is already installed** — go Electron for the best-looking result.
- If **Python is already installed** — go Python for the fastest build time.
- If you need the **smallest possible distributable** — Tauri (but install Rust first).
- If this will run on **non-Windows machines** — Electron or Python.
- If you want to **match the existing HTML report style exactly** — Electron.

---

*Tell EntraScope which option you've chosen and the full GUI will be built immediately.*
