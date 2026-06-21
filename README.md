# Yumiko Memory Analyzer

---

## Overview

**Yumiko Memory Analyzer** is a Windows-based tool that scans Minecraft Java process memory to detect cheat clients, cheat modules, injection APIs, and evasion techniques. It uses the Aho-Corasick algorithm for high-performance multi-pattern matching across both ASCII and UTF-16 encoded strings.

Unlike file-based scanners, Yumiko operates on live process memory — meaning it can detect cheats that try to hide or obfuscate their on-disk presence. Even cheat clients that attempt to self-destruct leave traces in memory and the JVM command line that Yumiko can identify.

## Features

- **Fast memory scanning** using Aho-Corasick automaton for simultaneous pattern matching
- **Dual encoding support** — scans both ASCII and UTF-16LE strings in process memory
- **Cheat client detection** — identifies 100+ known cheat clients by name, domain, and package paths
- **Cheat module detection** — covers combat, crystal/anchor, totem, movement, utility, ESP/vision, and evasion categories
- **Self-destruct awareness** — distinguishes between active and self-destructed cheat clients
- **Special DoomsdayClient handling** — suppresses all flags and shows only `DoomsdayClient detected` for clean reporting
- **Argon Client detection** — full support including `EncryptedString` XOR cipher and self-destruct via JNA memory purge
- **Injection API detection** — identifies process, window, memory, and execution injection techniques
- **Threat scoring** — assigns CLEAN / LOW / MEDIUM / HIGH / CRITICAL levels with detailed reasons
- **Live monitoring** — continuous scanning with configurable interval
- **Deep scan mode** — scans all memory regions including unmapped pages
- **JSON output** — machine-readable scan results for integration with other tools
- **Progress indicators** — real-time feedback during scanning

## Requirements

- **OS:** Windows (uses Windows API for memory access)
- **Python:** 3.8 or later
- **Privileges:** Administrator (required for memory scanning)
- **Dependencies:** `psutil`, `pyahocorasick`

## Installation

```bash
# Clone the repository
git clone https://github.com/veridondevvv/Yumiko-Memory-Analyzer.git
cd Yumiko-Memory-Analyzer

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Quick Start (Batch File)

Run `start_scanner.bat` as Administrator and select a scan mode:

```
1) Single scan
2) Continuous scan (every 5 seconds)
3) Scan specific PID
4) Deep scan (all memory regions)
```

### Command Line

```bash
# Scan all Minecraft processes
python minecraft_cheat_scanner.py

# Continuous monitoring (scans every 5 seconds)
python minecraft_cheat_scanner.py --continuous --interval 5

# Scan a specific PID
python minecraft_cheat_scanner.py --pid 12345

# Deep scan (all memory regions, slower but more thorough)
python minecraft_cheat_scanner.py --deep

# Verbose output
python minecraft_cheat_scanner.py --verbose

# Set scan timeout (seconds)
python minecraft_cheat_scanner.py --timeout 120
```

### Options

| Flag | Description |
|------|-------------|
| `--continuous` | Enable continuous monitoring mode |
| `--interval N` | Seconds between scans in continuous mode (default: 5) |
| `--pid PID` | Scan a specific process ID |
| `--deep` | Scan all memory regions (slower, more thorough) |
| `--verbose` | Show detailed scan progress |
| `--timeout N` | Maximum scan time in seconds |

## How It Works

### Memory Scanning

Yumiko opens the target Java process using the Windows API (`OpenProcess` with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`) and iterates over its virtual memory regions using `VirtualQueryEx`. Each committed, readable region is read with `ReadProcessMemory` and scanned for cheat patterns.

### Pattern Matching

Patterns are compiled into an Aho-Corasick automaton for simultaneous multi-pattern matching. This allows scanning hundreds of patterns in a single pass through each memory region. Both ASCII and UTF-16LE encodings are checked.

### Detection Categories

| Category | Description |
|----------|-------------|
| `CHEAT_CLIENT` | Cheat client names, domains, and package paths |
| `CHEAT_MODULE_COMBAT` | KillAura, AimBot, TriggerBot, AutoMace, etc. |
| `CHEAT_MODULE_CRYSTAL_ANCHOR` | AutoCrystal, AnchorMacro, SafeAnchor, etc. |
| `CHEAT_MODULE_TOTEM` | AutoTotem, HoverTotem, ForceTotem, etc. |
| `CHEAT_MODULE_MOVEMENT` | Fly, Speed, Strafe, Velocity, NoFall, etc. |
| `CHEAT_MODULE_UTILITY` | AutoEat, ChestStealer, AutoSell, etc. |
| `CHEAT_MODULE_ESP_VISION` | PlayerESP, XRay, Tracers, LightESP, etc. |
| `CHEAT_MODULE_EVASION` | FakeLag, PingSpoof, SelfDestruct, etc. |
| `CHEAT_INJECTOR` | Bytecode injection and Java-Agent signatures |
| `CHEAT_CONFIG` | Cheat configuration files and references |
| `INJECTION_API_*` | Process, window, memory, and execution injection APIs |

### Threat Scoring

| Level | Score | Meaning |
|-------|-------|---------|
| **CRITICAL** | 70+ | Cheat client or self-destructed client confirmed |
| **HIGH** | 40+ | Multiple cheat modules or injection signatures found |
| **MEDIUM** | 20+ | Some cheat patterns detected |
| **LOW** | 10+ | Minor suspicious patterns |
| **CLEAN** | <10 | No significant cheat patterns found |

### Special Client Handling

#### DoomsdayClient

When `doomsdayclient.xyz` is found in memory, Yumiko suppresses all other flags and displays only `DoomsdayClient detected`. If the client has self-destructed, `theseus.jar` (the Java agent JAR) is still visible in the JVM command line and triggers `DoomsdayClient detected (Self-Destructed)`.

#### Argon Client

Yumiko detects the Argon ghost client through its package paths (`dev.lvstrng.argon`), class names (`Argon.INSTANCE`, `ModuleManager`), and encrypted string utility (`EncryptedString`). After self-destruct, module names are nulled but `SelfDestruct.destruct`, `Memory.purge`, and `Memory.disposeAll` traces remain, triggering `Argon Client detected (Self-Destructed)`.

## Output

### Console Report

The scanner generates a color-coded console report including:
- Process information (PID, name, type, version, command line)
- Threat level and score
- Detailed reasons for the threat assessment
- Found cheat patterns grouped by category with memory addresses and context

### JSON Output

Scan results are also saved as JSON files (`cheat_scan_YYYYMMDD_HHMMSS.json`) containing:
- Process metadata
- Threat assessment (level, score, reasons)
- All found patterns with addresses and context strings

## Detected Clients

A non-exhaustive list of cheat clients Yumiko can detect:

- Wurst, Meteor, Impact, LiquidBounce, RusherHack
- Vape, VapeV4, Vape Lite
- Novoline, Salhack, KamiBlue, BleachHack
- DoomsdayClient (with self-destruct detection)
- Argon (with self-destruct detection)
- ZeroDay, Inertia, Vortex, Sigma, Aristois
- Future, Rise, Thunderhack, Zeon, Zephyr
- CrossSine, Ascension, Raven, Xatz, Blade
- Slinky, Staler, Tenacity, Augustus, Prestige
- Flux, Entropy, Eclipse, Genesis, Astral
- Trillium, Pyro, Phobos, Pandora, Centred
- Moon, Tenebra, Constellation, Subside, Slade
- And many more...

## Project Structure

```
Yumiko-Memory-Analyzer/
├── minecraft_cheat_scanner.py   # Main scanner script
├── java_monitor.py              # Java process monitor
├── start_scanner.bat            # Quick-start batch file
├── start_monitor.bat            # Monitor batch file
├── requirements.txt             # Python dependencies
├── CHANGELOG.md                 # Version history
├── DISCORD_UPDATE.md            # Discord announcement template
└── README.md                    # This file
```

## Limitations

- **Windows only** — uses Windows API for process memory access
- **Administrator required** — memory scanning needs elevated privileges
- **Java processes only** — scans `java.exe`, `javaw.exe`, and related JVM processes
- **Memory-based** — cannot detect cheats that have fully unloaded from memory
- **Pattern-based** — relies on known signatures; novel or heavily obfuscated cheats may evade detection

## Disclaimer

Yumiko Memory Analyzer is intended for **server administrators and anti-cheat developers** to identify potential cheat clients on systems under their control. It should only be used on processes and systems you own or have explicit permission to scan. Unauthorized scanning of other users' processes may violate privacy laws and terms of service.

## Links

- **GitHub:** [https://github.com/veridondevvv](https://github.com/veridondevvv)
- **Discord:** veridondevvv
- **Version:** 2.0

---

<p align="center">
  <em>Yumiko Memory Analyzer — See what others can't.</em>
</p>
