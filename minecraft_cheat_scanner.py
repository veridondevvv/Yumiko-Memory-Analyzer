"""
Yumiko Memory Analyzer
======================
Scans Java processes for cheats in memory.

Usage:
  python minecraft_cheat_scanner.py
  python minecraft_cheat_scanner.py --pid 12345
  python minecraft_cheat_scanner.py --continuous --interval 5
  python minecraft_cheat_scanner.py --output scan_report.json
  python minecraft_cheat_scanner.py --deep
"""

import argparse
import ctypes
import datetime
import json
import os
import re
import subprocess
import sys
import time

from collections import defaultdict

GITHUB_URL = "https://github.com/veridondevvv"
DISCORD_TAG = "veridondevvv"
SCANNER_NAME = "Yumiko Memory Analyzer"
SCANNER_VERSION = "2.1"

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BG_RED  = "\033[41m"
BG_BLUE = "\033[44m"
BG_MAG  = "\033[45m"

THREAT_COLORS = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "LOW":      GREEN,
    "CLEAN":    GREEN,
}


def enable_ansi():
    if os.name != "nt":
        return
    try:
        k = ctypes.windll.kernel32
        handle = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(handle, ctypes.byref(mode)):
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            k.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        pass
    try:
        os.system("")
    except Exception:
        pass
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    import psutil
except ImportError:
    print("[INFO] psutil not found. Installing...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", "psutil"],
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("[ERROR] pip install timed out. Please install psutil manually: pip install psutil")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] pip install failed (exit {e.returncode}). Please install psutil manually: pip install psutil")
        sys.exit(1)
    import psutil


try:
    import ahocorasick
    _HAVE_AC = True
except ImportError:
    print("[INFO] pyahocorasick not found. Installing for fast scanning...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir",
             "--only-binary", ":all:", "pyahocorasick"],
            timeout=120,
        )
        import ahocorasick
        _HAVE_AC = True
    except Exception:
        print("[WARN] pyahocorasick unavailable - falling back to slower regex scanning.")
        _HAVE_AC = False


kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
user32 = ctypes.windll.user32

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("PartitionId", ctypes.c_ushort),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("th32ModuleID", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("GlblcntUsage", ctypes.c_ulong),
        ("ProccntUsage", ctypes.c_ulong),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", ctypes.c_ulong),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


MEM_COMMIT = 0x00001000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

WRITABLE_PROTECTIONS = {
    PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
}

MAX_ADDRESS = 0x7FFFFFFFFFFF
MAX_REGION_SIZE = 4 * 1024 * 1024
MAX_TOTAL_SCAN = 1024 * 1024 * 1024
MAX_SCAN_SECONDS = 45
MAX_FOUND_STRINGS = 400
MAX_FOUND_PATTERNS = 4000
PER_PATTERN_CAP = 25

ASCII_STRING_RE = re.compile(rb'[\x20-\x7E]{6,}')
UNICODE_STRING_RE = re.compile(rb'(?:[\x20-\x7E]\x00){6,}')


INJECTION_API_PROCESS = [
    b"OpenProcess", b"NtOpenProcess", b"ZwOpenProcess",
    b"CreateToolhelp32Snapshot",
    b"Process32First", b"Process32FirstW",
    b"Process32Next", b"Process32NextW",
    b"EnumProcesses", b"EnumProcessModules",
    b"Module32First", b"Module32Next",
    b"PROCESSENTRY32", b"MODULEENTRY32",
    b"CreateToolhelp32Snapshot",
]

INJECTION_API_WINDOW = [
    b"FindWindowA", b"FindWindowW",
    b"FindWindowExA", b"FindWindowExW",
    b"GetWindowTextA", b"GetWindowTextW",
    b"GetClassNameA", b"GetClassNameW",
    b"EnumWindows", b"GetForegroundWindow",
    b"GetWindowThreadProcessId",
]

INJECTION_API_MEMORY = [
    b"ReadProcessMemory", b"WriteProcessMemory",
    b"VirtualAllocEx", b"VirtualProtectEx", b"VirtualFreeEx",
    b"NtReadVirtualMemory", b"NtWriteVirtualMemory",
    b"NtAllocateVirtualMemory", b"NtProtectVirtualMemory",
    b"ZwAllocateVirtualMemory", b"ZwProtectVirtualMemory",
    b"ZwWriteVirtualMemory",
]

INJECTION_API_EXEC = [
    b"CreateRemoteThread", b"CreateRemoteThreadEx",
    b"NtCreateThreadEx", b"ZwCreateThreadEx",
    b"RtlCreateUserThread",
    b"QueueUserAPC", b"NtQueueApcThread",
    b"SetWindowsHookExA", b"SetWindowsHookExW",
]

INJECTION_API_MISC = [
    b"LoadLibraryA", b"LoadLibraryW",
    b"LoadLibraryExA", b"LoadLibraryExW",
    b"GetProcAddress", b"GetModuleHandleA", b"GetModuleHandleW",
    b"ntdll.dll", b"NTDLL.dll",
    b"kernel32.dll", b"Kernel32.dll",
    b"user32.dll", b"User32.dll",
]

ALL_INJECTION_APIS = {
    "PROCESS_SEARCH": INJECTION_API_PROCESS,
    "WINDOW_SEARCH": INJECTION_API_WINDOW,
    "MEMORY_MANIPULATION": INJECTION_API_MEMORY,
    "CODE_EXECUTION": INJECTION_API_EXEC,
    "MISC_LOADING": INJECTION_API_MISC,
}

CHEAT_CLIENTS = [
    b"Wurst", b"wurst",
    b"Meteor", b"meteor-client", b"MeteorClient",
    b"ImpactClient", b"impact-client",
    b"Baritone", b"baritone",
    b"Inertia", b"inertia-client",
    b"SigmaClient", b"sigma-client",
    b"RusherHack", b"rusherhack",
    b"VortexClient", b"vortex-client",
    b"AquaClient", b"aqua-client",
    b"Aristois", b"aristois",
    b"Doomsday", b"DoomsdayClient", b"doomsday-client", b"DoomsdayClient.jar",
    b"DoomsdayHack", b"doomsday-hack", b"DoomsdayMod", b"doomsday-mod",
    b"DoomsdayLoader", b"doomsday-loader", b"DoomsdayInject", b"doomsday-inject",
    b"DoomsdayBypass", b"doomsday-bypass", b"DoomsdayGUI", b"doomsday-gui",
    b"DoomsdayMenu", b"doomsday-menu", b"DoomsdayConfig", b"doomsday-config",
    b"DoomsdayHook", b"doomsday-hook", b"DoomsdayModule", b"doomsday-module",
    b"DoomsdayManager", b"doomsday-manager", b"DoomsdayCore", b"doomsday-core",
    b"DoomsdayEvent", b"doomsday-event", b"DoomsdaySetting", b"doomsday-setting",
    b"DoomsdayCommand", b"doomsday-command", b"DoomsdayUtil", b"doomsday-util",
    b"DoomsdayPath", b"doomsday-path", b"DoomsdayMixin", b"doomsday-mixin",
    b"DoomsdayShader", b"doomsday-shader", b"DoomsdayRender", b"doomsday-render",
    b"DoomsdayPacket", b"doomsday-packet", b"DoomsdayNet", b"doomsday-net",
    b"DoomsdayAuth", b"doomsday-auth", b"DoomsdayLicense", b"doomsday-license",
    b"DoomsdayUpdate", b"doomsday-update", b"DoomsdayJson", b"doomsday-json",
    b"DoomsdaySocket", b"doomsday-socket", b"DoomsdayProxy", b"doomsday-proxy",
    b"DoomsdayCrypt", b"doomsday-crypt", b"DoomsdayObf", b"doomsday-obf",
    b"DoomsdayAntiDump", b"doomsday-antidump", b"DoomsdayAntiDebug", b"doomsday-antidebug",
    b"DoomsdaySelfDestruct", b"doomsday-selfdestruct", b"DoomsdayCleaner", b"doomsday-cleaner",
    b"Argon", b"argon-client", b"ArgonClient", b"argon-b1", b"dev.lvstrng.argon",
    b"lvstrng", b"LvStrnggg", b"EncryptedString", b"Argon.INSTANCE",
    b"SelfDestruct.destruct", b"argonJar", b"resetModifiedDate",
    b"ModuleManager", b"ProfileManager", b"FriendManager", b"RotatorManager",
    b"Memory.purge", b"Memory.disposeAll",
    b"DoomsdayStealer", b"doomsday-stealer", b"DoomsdayXRay", b"doomsday-xray",
    b"DoomsdayAura", b"doomsday-aura", b"DoomsdayFly", b"doomsday-fly",
    b"DoomsdaySpeed", b"doomsday-speed", b"DoomsdayESP", b"doomsday-esp",
    b"DoomsdayScaffold", b"doomsday-scaffold", b"DoomsdayAutoCrystal", b"doomsday-autocrystal",
    b"DoomsdayAutoTotem", b"doomsday-autototem", b"DoomsdayAutoAnchor", b"doomsday-autoanchor",
    b"DoomsdayKillAura", b"doomsday-killaura", b"DoomsdayCrystal", b"doomsday-crystal",
    b"DoomsdayAnchor", b"doomsday-anchor", b"DoomsdayTotem", b"doomsday-totem",
    b"DoomsdayVelocity", b"doomsday-velocity", b"DoomsdayReach", b"doomsday-reach",
    b"DoomsdayNoFall", b"doomsday-nofall", b"DoomsdaySprint", b"doomsday-sprint",
    b"DoomsdaySneak", b"doomsday-sneak", b"DoomsdayFastPlace", b"doomsday-fastplace",
    b"DoomsdayFastBreak", b"doomsday-fastbreak", b"DoomsdayTimer", b"doomsday-timer",
    b"DoomsdayFakeLag", b"doomsday-fakelag", b"DoomsdayPingSpoof", b"doomsday-pingspoof",
    b"DoomsdayBlink", b"doomsday-blink", b"DoomsdayFreeCam", b"doomsday-freecam",
    b"DoomsdayNoClip", b"doomsday-noclip", b"DoomsdayPhase", b"doomsday-phase",
    b"DoomsdayAutoClick", b"doomsday-autoclick", b"DoomsdayClickGUI", b"doomsday-clickgui",
    b"DoomsdayHud", b"doomsday-hud", b"DoomsdayTabGui", b"doomsday-tabgui",
    b"DoomsdayArrayList", b"doomsday-arraylist", b"DoomsdayWatermark", b"doomsday-watermark",
    b"DoomsdayNotifications", b"doomsday-notifications", b"DoomsdayColors", b"doomsday-colors",
    b"DoomsdayFont", b"doomsday-font", b"DoomswayRainbow", b"doomsday-rainbow",
    b"DoomsdayChams", b"doomsday-chams", b"DoomsdayTracer", b"doomsday-tracer",
    b"DoomsdayNameTags", b"doomsday-nametags", b"DoomsdayStorageESP", b"doomsday-storageesp",
    b"DoomsdayEntityESP", b"doomsday-entityesp", b"DoomsdayPlayerESP", b"doomsday-playeresp",
    b"DoomsdayFullBright", b"doomsday-fullbright", b"DoomsdayNightVision", b"doomsday-nightvision",
    b"DoomsdayZoom", b"doomsday-zoom", b"DoomsdayTrajectories", b"doomsday-trajectories",
    b"DoomsdaySearch", b"doomsday-search", b"DoomsdayNuker", b"doomsday-nuker",
    b"DoomsdaySurround", b"doomsday-surround", b"DoomsdayHoleFill", b"doomsday-holefill",
    b"DoomsdaySelfTrap", b"doomsday-selftrap", b"DoomsdayBurrow", b"doomsday-burrow",
    b"DoomsdayAutoArmor", b"doomsday-autoarmor", b"DoomsdayAutoTool", b"doomsday-autotool",
    b"DoomsdayAutoEat", b"doomsday-autoeat", b"DoomsdayAutoPot", b"doomsday-autopot",
    b"DoomsdayChestStealer", b"doomsday-cheststealer", b"DoomsdayScaffold", b"doomsday-scaffold",
    b"DoomsdayTower", b"doomsday-tower", b"DoomsdayFastBow", b"doomsday-fastbow",
    b"DoomsdayFastEat", b"doomsday-fasteat", b"DoomsdayAntiAFK", b"doomsday-antiafk",
    b"DoomsdayAutoFish", b"doomsday-autofish", b"DoomsdayAutoFarm", b"doomsday-autofarm",
    b"DoomsdayAutoSell", b"doomsday-autosell", b"DoomsdaySpammer", b"doomsday-spammer",
    b"DoomswayAutoGG", b"doomsday-autogg", b"DoomsdayAutoEZ", b"doomsday-autoez",
    b"DoomsdayAutoL", b"doomsday-autol", b"DoomsdayAutoQueue", b"doomsday-autoqueue",
    b"DoomsdayAutoReconnect", b"doomsday-autoreconnect", b"DoomsdayAutoLogin", b"doomsday-autologin",
    b"DoomsdayPathFinder", b"doomsday-pathfinder", b"DoomsdayMineBot", b"doomsday-minebot",
    b"DoomsdayBaritone", b"doomsday-baritone", b"DoomsdaySword", b"doomsday-sword",
    b"DoomsdayGapple", b"doomsday-gapple", b"DoomsdayRefill", b"doomsday-refill",
    b"DoomsdayMiddleClick", b"doomsday-middleclick", b"DoomsdayPearl", b"doomsday-pearl",
    b"DoomsdayKeyPearl", b"doomsday-keypearl", b"DoomsdayCordSnapper", b"doomsday-cordsnapper",
    b"DoomsdayBedMacro", b"doomsday-bedmacro", b"DoomsdayAutoTpa", b"doomsday-autotpa",
    b"DoomsdayAutoRestock", b"doomsday-autorestock", b"DoomsdayReplaceMod", b"doomsday-replacemod",
    b"DoomsdayStringCleaner", b"doomsday-stringcleaner", b"DoomsdayAntiSS", b"doomsday-antiss",
    b"DoomsdayUSNCleaner", b"doomsday-usncleaner", b"DoomsdayGhost", b"doomsday-ghost",
    b"DoomsdayDesync", b"doomsday-desync", b"DoomsdayAntiBot", b"doomsday-antibot",
    b"DoomsdayBlockBypass", b"doomsday-blockbypass", b"DoomsdayStrayBypass", b"doomsday-straybypass",
    b"DoomsdayDonutBypass", b"doomsday-donutbypass", b"DoomsdayPackSpoof", b"doomsday-packspoof",
    b"DoomsdayMaceAura", b"doomsday-maceaura", b"DoomsdaySilentMace", b"doomsday-silentmace",
    b"DoomsdaySilentAim", b"doomsday-silentaim", b"DoomsdayAimAssist", b"doomsday-aimassist",
    b"DoomsdayBowAimbot", b"doomsday-bowaimbot", b"DoomsdayTriggerBot", b"doomsday-triggerbot",
    b"DoomsdayAntiWeakness", b"doomsday-antiweakness", b"DoomsdayDamageTick", b"doomsday-damagetick",
    b"DoomsdayOnlyCrit", b"doomsday-onlycrit", b"DoomsdayShieldDisabler", b"doomsday-shielddisabler",
    b"DoomsdayAntiInvis", b"doomsday-antiinvis", b"DoomsdayWTap", b"doomsday-wtap",
    b"DoomsdayAutoAura", b"doomsday-autoaura", b"DoomsdayCriticals", b"doomsday-criticals",
    b"DoomsdayHitBox", b"doomsday-hitbox", b"DoomsdayStaticHitbox", b"doomsday-statichitbox",
    b"DoomsdayFakePunch", b"doomsday-fakepunch", b"DoomsdayCwCrystal", b"doomsday-cwcrystal",
    b"DoomsdayMarlowAnchor", b"doomsday-marlowanchor", b"DoomsdayDoubleAnchor", b"doomsday-doubleanchor",
    b"DoomsdayAnchorExploder", b"doomsday-anchorexploder", b"DoomsdayAutoDtap", b"doomsday-autodtap",
    b"DoomsdayAntiAntiCw", b"doomsday-antianticw", b"DoomsdayAutoHitCrystal", b"doomsday-autohitcrystal",
    b"DoomsdayCrystalOptimizer", b"doomsday-crystaloptimizer", b"DoomsdayTotemOffhand", b"doomsday-totemoffhand",
    b"DoomsdayHoverTotem", b"doomsday-hovertotem", b"DoomsdayForceTotem", b"doomsday-forcetotem",
    b"DoomsdayAutoRetotem", b"doomsday-autoretotem", b"DoomsdayAutoDoubleHand", b"doomsday-autodoublehand",
    b"DoomsdayFastBridge", b"doomsday-fastbridge", b"DoomsdayBridgeAssist", b"doomsday-bridgeassist",
    b"DoomsdayFastSwim", b"doomsday-fastswim", b"DoomsdayNoBreakDelay", b"doomsday-nobreakdelay",
    b"DoomsdayNoJumpDelay", b"doomsday-nojumpdelay", b"DoomsdayElytraSwap", b"doomsday-elytraswap",
    b"DoomsdayElytraGlide", b"doomsday-elytraglide", b"DoomsdayJetpack", b"doomsday-jetpack",
    b"DoomsdayAutoSprint", b"doomsday-autosprint", b"DoomsdayInvMove", b"doomsday-invmove",
    b"DoomsdayPacketFly", b"doomsday-packetfly", b"DoomsdayHighJump", b"doomsday-highjump",
    b"DoomsdayStep", b"doomsday-step", b"DoomsdayJesus", b"doomsday-jesus",
    b"DoomsdayEntitySpeed", b"doomsday-entityspeed", b"DoomsdayTrident", b"doomsday-trident",
    b"DoomsdayNoWeb", b"doomsday-noweb", b"DoomsdayAntiWater", b"doomsday-antiwater",
    b"DoomsdayAutoWalk", b"doomsday-autowalk", b"DoomsdaySafeWalk", b"doomsday-safewalk",
    b"DoomsdayBlockReach", b"doomsday-blockreach", b"DoomsdayNoRotate", b"doomsday-norotate",
    b"DoomsdayNoSlowDown", b"doomsday-noslowdown", b"DoomsdayAntiVoid", b"doomsday-antivoid",
    b"DoomsdayAntiHunger", b"doomsday-antihunger", b"DoomsdayDerp", b"doomsday-derp",
    b"DoomsdayHeadRoll", b"doomsday-headroll", b"DoomsdayVelocity", b"doomsday-velocity",
    b"DoomsdaySneak", b"doomsday-sneak", b"DoomsdayStorageHack", b"doomsday-storagehack",
    b"DoomsdayFOV", b"doomsday-fov", b"DoomsdayFreeLook", b"doomsday-freelook",
    b"DoomsdayCameraDistance", b"doomsday-cameradistance", b"DoomsdayAspectRatio", b"doomsday-aspectratio",
    b"DoomsdayNoHurtCam", b"doomsday-nohurtcam", b"DoomsdayNoBob", b"doomsday-nobob",
    b"DoomsdayNoWeather", b"doomsday-noweather", b"DoomsdayGamma", b"doomsday-gamma",
    b"DoomsdayHealthIndicators", b"doomsday-healthindicators", b"DoomsdayTargetHUD", b"doomsday-targethud",
    b"DoomsdayNetheriteFinder", b"doomsday-netheritefinder", b"DoomsdayRtpBaseFinder", b"doomsday-rtpbasefinder",
    b"DoomsdayWallHack", b"doomsday-wallhack", b"DoomsdayAutoMine", b"doomsday-automine",
    b"DoomsdayShulkerDropper", b"doomsday-shulkerdropper", b"DoomsdayAutoAnvil", b"doomsday-autoanvil",
    b"DoomsdayAutoBow", b"doomsday-autobow", b"DoomsdayAutoSoup", b"doomsday-autosoup",
    b"DoomsdayAutoSteal", b"doomsday-autosteal", b"DoomsdayAutoRespawn", b"doomsday-autorespawn",
    b"DoomsdayOffHand", b"doomsday-offhand", b"DoomsdayFakePlayer", b"doomsday-fakeplayer",
    b"DoomsdayArrowDodge", b"doomsday-arrowdodge", b"DoomsdayAntiFireball", b"doomsday-antifireball",
    b"DoomsdayFastUse", b"doomsday-fastuse", b"DoomsdayFastItem", b"doomsday-fastitem",
    b"DoomsdayInventoryTotemLegit", b"doomsday-inventorytotemlegit",

    b"FutureClient", b"future-client",
    b"Salhack", b"salhack",
    b"KamiBlue", b"kami-blue", b"KAMI",
    b"ZeroDay", b"zeroday",
    b"ExpensiveClient", b"expensive-client",
    b"Dreamy",
    b"RiseClient", b"rise-client",
    b"Nullify",
    b"Novoline", b"novoline",
    b"SlinkyClient", b"slinky-client",
    b"Thunderhack", b"thunderhack",
    b"ZeonClient", b"zeon-client",
    b"ZephyrClient", b"zephyr-client",
    b"BleachHack", b"bleachhack",
    b"CatalystClient", b"catalyst-client",
    b"CrystalClient", b"crystal-client",
    b"FDPClient", b"fdp-client",
    b"GhostClient", b"ghost-client",
    b"InfernoClient", b"inferno-client",
    b"LambdaClient", b"lambda-client",
    b"NightX",
    b"NitroClient", b"nitro-client",
    b"ParticleClient", b"particle-client",
    b"PhantomClient", b"phantom-client",
    b"PoohClient", b"pooh-client",
    b"SmokeClient", b"smoke-client",
    b"StalerClient", b"staler-client",
    b"Vape", b"VapeV4", b"Vape Lite", b"vape",
    b"Akrien",
    b"MetaClient", b"meta-client",
    b"NoComHack", b"nocom-hack",
    b"RusherHack",
    b"TestClient",
    b"hacked-client", b"HackedClient",
    b"hack-client", b"HackClient",
    b"cheat-client", b"CheatClient",
    b"utility-mod", b"UtilityMod",
    b"ghost-client",
    b"injection-client",
    b"AtomClient", b"atom-client",
    b"RavenClient", b"raven-client",
    b"XatzClient", b"xatz-client",
    b"CrossSine", b"crosssine",
    b"ZenClient", b"zen-client",
    b"AscensionClient", b"ascension-client",
    b"BladeClient", b"blade-client",
    b"LiquidBounce", b"liquidbounce", b"LiquidBounceClient",
    b"Tenacity", b"TenacityClient",
    b"Augustus", b"AugustusClient",
    b"Prestige", b"PrestigeClient",
    b"FluxClient", b"flux-client",
    b"EntropyClient", b"entropy-client",
    b"EclipseClient", b"eclipse-client",
    b"GenesisClient", b"genesis-client",
    b"AstralClient", b"astral-client",
    b"Trillium", b"TrilliumClient",
    b"PyroClient", b"pyro-client",
    b"Phobos", b"PhobosClient",
    b"Pandora", b"PandoraClient",
    b"Centred", b"CentredClient",
    b"MoonClient", b"Moon Client",
    b"Tenebra", b"TenebraClient",
    b"Constellation", b"ConstellationClient",
    b"Subside", b"SubsideClient",
    b"Slade", b"SladeClient",
    b"FDPClient", b"fdp-client",
    b"3arthh4ck", b"earthhack",
    b"Seppuku", b"SeppukuClient",
    b"TrouserStreak", b"Trouser-Streak",
    b"Pandaware", b"Wexside", b"Nulline", b"Exhibition",
    b"Komorebi", b"Rinami", b"Vergil", b"Koid",
    b"Sakura", b"SakuraClient",
    b"Photon", b"PhotonClient",
    b"Wavy", b"WavyClient", b"Cinnabar",
    b"Bypass",
]

CHEAT_MODULES_COMBAT = [
    b"KillAura", b"killaura", b"Kill_Aura", b"Kill Aura",
    b"CrystalAura", b"Crystal Aura", b"crystalaura",
    b"MaceAura", b"Mace Aura", b"maceaura",
    b"SilentMace", b"Silent Mace", b"silentmace",
    b"AimAssist", b"Aim Assist", b"aimassist",
    b"SilentAim", b"Silent Aim", b"silentaim",
    b"BowAimbot", b"Bow Aimbot", b"bowaimbot",
    b"TriggerBot", b"triggerbot", b"Trigger Bot",
    b"AntiWeakness", b"Anti Weakness", b"antiweakness",
    b"FakePunch", b"Fake Punch", b"fakepunch",
    b"DamageTick", b"Damage Tick", b"damagetick",
    b"OnlyCrit", b"Only Crit", b"onlycrit",
    b"StaticHitbox", b"Static HitBoxes", b"statichitbox",
    b"ShieldDisabler", b"Shield Disabler", b"shielddisabler",
    b"ShieldBreaker", b"Shield Breaker", b"shieldbreaker",
    b"AntiInvis", b"Anti Invis", b"antiinvis",
    b"WTap", b"W-Tap", b"wtap",
    b"AimBot", b"aimbot", b"Aimbot",
    b"AutoAura", b"autoaura",
    b"Reach", b"reach-hack", b"ReachHack",
    b"Criticals", b"criticals-hack",
    b"Hitboxes", b"hitboxes", b"Hitbox", b"hitbox-hack",
    b"MaceCombo", b"Mace Combo", b"macecombo",
    b"MaceSpam", b"Mace Spam", b"macespam",
    b"BowSpam", b"Bow Spam", b"bowspam",
    b"AutoCrit", b"Auto Crit", b"autocrit",
    b"Backtrack", b"BackTrack",
    b"HitboxExpand", b"Hitbox Expand", b"hitboxexpand",
    b"AutoBlock", b"Auto Block", b"autoblock",
    b"AntiAim", b"Anti Aim", b"antiaim",
    b"Spinbot", b"SpinBot", b"spinbot",
    b"PotAimbot", b"Pot Aimbot", b"potaimbot",
    b"MaceInsta", b"Mace Insta", b"maceinsta",
    b"OneTapMace", b"One Tap Mace", b"onetapmace",
    b"WitherAura", b"Wither Aura", b"witheraura",
    b"BedAura", b"Bed Aura", b"bedaura",
    b"AnvilAura", b"Anvil Aura", b"anvilaura",
    b"BlatantAura", b"Blatant Aura", b"blatantaura",
    b"LegitAura", b"Legit Aura", b"legitaura",
    b"PvPAssist", b"PvP Assist", b"pvpassist",
    b"AnchorMacro", b"Anchor Macro", b"anchormacro",
    b"NoMissDelay", b"No Miss Delay", b"nomissdelay",
    b"AutoWTap", b"Auto WTap", b"autowtap",
    b"AutoMace", b"Auto Mace", b"automace",
    b"StunSlam", b"Stun Slam", b"stunslam",
    b"MaceSwap", b"Mace Swap", b"maceswap",
]

CHEAT_MODULES_CRYSTAL_ANCHOR = [
    b"AutoCrystal", b"Auto Crystal", b"autocrystal",
    b"CrystalOptimizer", b"Crystal Optimizer", b"crystaloptimizer",
    b"CwCrystal", b"Cw Crystal", b"cwcrystal",
    b"DoubleAnchor", b"Double Anchor", b"doubleanchor",
    b"AnchorExploder", b"Anchor Exploder", b"anchorexploder",
    b"AutoDtap", b"Auto Dtap", b"autodtap",
    b"MarlowAnchor", b"Marlow Anchor", b"marlowanchor",
    b"AntiAntiCw", b"Anti Anti Cw", b"antianticw",
    b"AutoHitCrystal", b"Auto Hit Crystal", b"autohitcrystal",
    b"AutoAnchor", b"Auto Anchor", b"autoanchor",
    b"AnchorAura", b"Anchor Aura", b"anchoraura",
    b"PistonAura", b"Piston Aura", b"pistonaura",
    b"SwapAura", b"Swap Aura", b"swapaura",
    b"AutoAnchorPlace", b"Auto Anchor Place", b"autoanchorplace",
    b"PopCounter", b"Pop Counter", b"popcounter",
    b"AutoDoubleAnchor", b"autodoubleanchor",
    b"CrystalPlace", b"Crystal Place", b"crystalplace",
    b"AutoGlow", b"autoglow",
    b"SafeAnchor", b"Safe Anchor", b"safeanchor",
]

CHEAT_MODULES_TOTEM = [
    b"AutoTotem", b"Auto Totem", b"autototem",
    b"TotemOffhand", b"Totem Offhand", b"totemoffhand",
    b"HoverTotem", b"Hover Totem", b"hovertotem",
    b"ForceTotem", b"Force Totem", b"forcetotem",
    b"AutoRetotem", b"Auto Retotem", b"autoretotem",
    b"InventoryTotemLegit", b"Inventory Totem Legit",
    b"AutoDoubleHand", b"Auto Double Hand", b"autodoublehand",
    b"OffhandTotem", b"Offhand Totem", b"offhandtotem",
    b"AutoPopTotem", b"Auto Pop Totem", b"autopoptotem",
    b"TotemPop", b"Totem Pop", b"totempop",
]

CHEAT_MODULES_MOVEMENT = [
    b"FastBridge", b"Fast Bridge", b"fastbridge",
    b"BridgeAssist", b"Bridge Assist", b"bridgeassist",
    b"FastSwim", b"Fast Swim", b"fastswim",
    b"FastPlace", b"Fast Place", b"fastplace",
    b"NoBreakDelay", b"No Break Delay", b"nobreakdelay",
    b"NoJumpDelay", b"No Jump Delay", b"nojumpdelay",
    b"ElytraSwap", b"Elytra Swap", b"elytraswap",
    b"ElytraGlide", b"Elytra Glide", b"elytraglide",
    b"Jetpack", b"jetpack",
    b"AutoSprint", b"Auto Sprint", b"autosprint",
    b"InventoryMove", b"InventoryMove", b"invmove",
    b"Fly", b"FlyHack", b"fly-hack",
    b"SpeedHack", b"speed-hack",
    b"NoFall", b"nofall", b"No Fall",
    b"NoClip", b"noclip", b"No Clip",
    b"phase-hack",
    b"PacketFly", b"packetfly",
    b"HighJump", b"highjump",
    b"step-hack",
    b"AntiKnockback", b"antiknockback",
    b"Jesus", b"jesus-hack",
    b"sneak-hack",
    b"EntitySpeed", b"entityspeed",
    b"trident-hack",
    b"NoWeb", b"noweb",
    b"AntiWater", b"antiwater",
    b"AutoWalk", b"autowalk",
    b"SafeWalk", b"safewalk",
    b"BlockReach", b"blockreach",
    b"NoRotate", b"norotate",
    b"NoSlowDown", b"noslowdown", b"NoSlow",
    b"AntiVoid", b"antivoid",
    b"AntiHunger", b"antihunger",
    b"Derp", b"derp-hack",
    b"HeadRoll", b"headroll",
    b"BoatFly", b"Boat Fly", b"boatfly",
    b"ElytraFly", b"Elytra Fly", b"elytrafly",
    b"ElytraTarget", b"Elytra Target", b"elytratarget",
    b"Strafe", b"strafe-hack", b"strafe",
    b"JumpReset", b"Jump Reset", b"jumpreset",
    b"AutoJumpReset", b"Auto Jump Reset", b"autojumpreset",
    b"Velocity", b"velocity-hack",
    b"OmniSprint", b"Omni Sprint", b"omnisprint",
    b"VClip", b"vclip", b"AutoVClip",
    b"AntiVanish", b"Anti Vanish", b"antivanish",
    b"NoPush", b"No Push", b"nopush", b"AntiPush",
    b"PacketMine", b"Packet Mine", b"packetmine",
    b"FastLadder", b"fastladder",
    b"spider-hack",
    b"glide-hack",
]

CHEAT_MODULES_UTILITY = [
    b"AutoClicker", b"Auto Clicker", b"autoclicker", b"AutoClick",
    b"AutoPot", b"Auto Pot", b"autopot",
    b"AutoEat", b"Auto Eat", b"autoeat",
    b"AutoXP", b"Auto XP", b"autoxp",
    b"AutoArmor", b"Auto Armor", b"autoarmor",
    b"AutoTool", b"Auto Tool", b"autotool",
    b"AutoMine", b"Auto Mine", b"automine",
    b"ChestStealer", b"Chest Stealer", b"cheststealer",
    b"ShulkerDropper", b"Shulker Dropper", b"shulkerdropper",
    b"AutoSell", b"Auto Sell", b"autosell",
    b"CordSnapper", b"Cord Snapper", b"cordsnapper",
    b"KeyPearl", b"Key Pearl", b"keypearl",
    b"AutoTpa", b"Auto Tpa", b"autotpa",
    b"BedMacro", b"Bed Macro", b"bedmacro",
    b"AutoRestock", b"Auto Restock", b"autorestock",
    b"ReplaceMod", b"Replace Mod", b"replacemod",
    b"AutoBed", b"Auto Bed", b"autobed",
    b"AutoAnvil", b"Auto Anvil", b"autoanvil",
    b"AutoBow", b"Auto Bow", b"autobow",
    b"AutoFish", b"Auto Fish", b"autofish",
    b"AutoFarm", b"Auto Farm", b"autofarm",
    b"AutoSoup", b"Auto Soup", b"autosoup",
    b"AutoSteal", b"Auto Steal", b"autosteal",
    b"AutoRespawn", b"Auto Respawn", b"autorespawn",
    b"AutoQueue", b"Auto Queue", b"autoqueue",
    b"AutoReconnect", b"Auto Reconnect", b"autoreconnect",
    b"AutoLogin", b"Auto Login", b"autologin",
    b"AutoL", b"Auto L", b"autol",
    b"AutoGG", b"Auto GG", b"autogg",
    b"AutoEZ", b"Auto EZ", b"autoez",
    b"Spammer", b"spammer-hack",
    b"Scaffold", b"scaffold-hack",
    b"Tower", b"tower-hack",
    b"Nuker", b"nuker-hack",
    b"Burrow", b"burrow-hack",
    b"Surround", b"surround-hack",
    b"HoleFill", b"holefill",
    b"SelfTrap", b"selftrap",
    b"FastBow", b"fastbow",
    b"FastEat", b"fasteat",
    b"FastUse", b"fastuse",
    b"FastBreak", b"fastbreak",
    b"FastItem", b"fastitem",
    b"AntiAfk", b"antiafk", b"AntiAFK",
    b"PathFinder", b"pathfinder",
    b"MineBot", b"minebot",
    b"TimerHack", b"timer-hack",
    b"OffHand", b"offhand-hack",
    b"FakePlayer", b"fakeplayer-hack",
    b"ArrowDodge", b"arrowdodge",
    b"AntiFireball", b"antifireball",
    b"ClickGUI", b"ClickGui", b"clickgui",
    b"AutoMend", b"Auto Mend", b"automend",
    b"PearlAura", b"Pearl Aura", b"pearlaura",
    b"WebAura", b"Web Aura", b"webaura",
    b"AutoPearl", b"Auto Pearl", b"autopearl",
    b"OffhandManager", b"Offhand Manager", b"offhandmanager",
    b"AutoGap", b"Auto Gap", b"autogap",
    b"GapMacro", b"Gap Macro", b"gapmacro",
    b"FastXP", b"Fast XP", b"fastxp",
    b"AutoDrop", b"Auto Drop", b"autodrop",
    b"FastDrop", b"Fast Drop", b"fastdrop",
    b"InvManager", b"Inventory Manager", b"invmanager",
    b"AutoLeave", b"Auto Leave", b"autoleave",
    b"AutoDisconnect", b"Auto Disconnect", b"autodisconnect",
    b"PacketEat", b"Packet Eat", b"packeteat",
    b"AutoCraft", b"Auto Craft", b"autocraft",
    b"AutoSmelt", b"autosmelt",
    b"AutoShulker", b"autoshulker",
    b"freeze-hack",
    b"Prevent", b"prevent-hack",
    b"NoBounce", b"No Bounce", b"nobounce",
    b"AutoPotRefill", b"Auto Pot Refill", b"autopotrefill",
    b"AutoInventoryTotem", b"Auto Inventory Totem", b"autoinventorytotem",
]

CHEAT_MODULES_ESP_VISION = [
    b"PlayerESP", b"Player ESP", b"playeresp",
    b"StorageESP", b"Storage ESP", b"storageesp",
    b"EntityESP", b"Entity ESP", b"entityesp",
    b"ESP", b"esp", b"esp-hack",
    b"BlockESP", b"Block ESP", b"blockesp",
    b"XRay", b"xray", b"X-Ray", b"x-ray",
    b"HealthIndicators", b"Health Indicators", b"healthindicators",
    b"TargetHUD", b"Target HUD", b"targethud",
    b"NetheriteFinder", b"Netherite Finder", b"netheritefinder",
    b"RtpBaseFinder", b"Rtp Base Finder", b"rtpbasefinder",
    b"Tracer", b"Tracers", b"tracers", b"tracer-hack",
    b"NameTags", b"nametags", b"nametags-hack",
    b"HUD", b"Hud", b"hud-hack",
    b"Chams", b"chams-hack",
    b"WallHack", b"wallhack",
    b"FullBright", b"fullbright", b"Fullbright",
    b"NightVision", b"nightvision",
    b"zoom-hack",
    b"NoHurtCam", b"nohurtcam",
    b"NoBob", b"nobob",
    b"NoWeather", b"noweather",
    b"Gamma", b"gamma-hack",
    b"Trajectories", b"trajectories",
    b"search-hack",
    b"StorageHack",
    b"fov-hack",
    b"FreeCam", b"Freecam", b"freecam",
    b"FreeLook", b"freelook",
    b"CameraDistance", b"cameradistance",
    b"AspectRatio", b"aspectratio",
    b"ItemESP", b"Item ESP", b"itemesp",
    b"ChestESP", b"Chest ESP", b"chestesp",
    b"MobESP", b"Mob ESP", b"mobesp",
    b"CrystalESP", b"Crystal ESP", b"crystalesp",
    b"BedESP", b"Bed ESP", b"bedesp",
    b"ContainerESP", b"Container ESP", b"containeresp",
    b"LogoutSpots", b"Logout Spots", b"logoutspots",
    b"radar-hack",
    b"TunnelBaseFinder", b"Tunnel Base Finder", b"tunnelbasefinder",
    b"LightFinder", b"Light Finder", b"lightfinder",
    b"LightESP", b"Light ESP", b"lightesp",
    b"LightDebug", b"Light Debug", b"lightdebug",
    b"FakeScoreboard", b"Fake Scoreboard", b"fakescoreboard",
]

CHEAT_MODULES_EVASION = [
    b"FakeLag", b"Fake Lag", b"fakelag",
    b"PingSpoof", b"Ping Spoof", b"pingspoof",
    b"PackSpoof", b"Pack Spoof", b"packspoof",
    b"StrayBypass", b"Stray Bypass", b"straybypass",
    b"DonutSMPBypass", b"Donut SMP Bypass", b"donutsmpbypass",
    b"Donut", b"donut-hack",
    b"SafeCart", b"Safe Cart", b"safecart",
    b"AntiSSTool", b"Anti SS Tool", b"antisstool",
    b"StringCleaner", b"String Cleaner", b"stringcleaner",
    b"SelfDestruct", b"Self Destruct", b"selfdestruct",
    b"USNJournalCleaner", b"USN Journal Cleaner", b"usnjournalcleaner",
    b"DeleteUSNJournal", b"Delete USN Journal", b"deleteusnjournal",
    b"GenericSelfdestruct", b"Generic Selfdestruct", b"genericselfdestruct",
    b"blink-hack",
    b"blockbypass",
    b"Desync", b"desync",
    b"ghost-mode",
    b"AntiScreenShare", b"Anti ScreenShare", b"antiscreenshare", b"AntiSS",
    b"ScreenShareBypass", b"ScreenShare Bypass", b"screensharebypass",
    b"ProcessHider", b"Process Hider", b"processhider", b"HideProcess",
    b"ClearLogs", b"Clear Logs", b"clearlogs",
    b"WipeTraces", b"Wipe Traces", b"wipetraces",
    b"PrefetchCleaner", b"Prefetch Cleaner", b"prefetchcleaner",
    b"DeleteRecent", b"Delete Recent", b"deleterecent",
    b"AntiForensics", b"Anti Forensics", b"antiforensics",
    b"JNativeHook", b"jnativehook",
    b"AntiStaff", b"Anti Staff", b"antistaff",
    b"StaffDetector", b"Staff Detector", b"staffdetector",
    b"AntiCheatBypass", b"Anticheat Bypass", b"anticheatbypass",
    b"GrimBypass", b"Grim Bypass", b"grimbypass",
    b"VulcanBypass", b"Vulcan Bypass", b"vulcanbypass",
    b"MatrixBypass", b"Matrix Bypass", b"matrixbypass",
    b"NCPBypass", b"NCP Bypass", b"ncpbypass",
    b"VerusBypass", b"Verus Bypass", b"verusbypass",
    b"PolarBypass", b"Polar Bypass", b"polarbypass",
    b"IntaveBypass", b"Intave Bypass", b"intavebypass",
    b"SpoofMods", b"Spoof Mods", b"spoofmods",
    b"BrandSpoofer", b"Brand Spoofer", b"brandspoofer",
    b"ChannelSpoof", b"channelspoof",
]

CHEAT_MODULES_WORLD = [
    b"NewChunks", b"New Chunks", b"newchunks",
    b"NewChunkDetector", b"newchunkdetector",
    b"StashFinder", b"Stash Finder", b"stashfinder",
    b"BaseFinder", b"Base Finder", b"basefinder",
    b"PortalFinder", b"Portal Finder", b"portalfinder",
    b"PacketNuker", b"Packet Nuker", b"packetnuker",
    b"FastMine", b"Fast Mine", b"fastmine",
    b"InstaMine", b"Insta Mine", b"instamine",
    b"SpeedMine", b"Speed Mine", b"speedmine",
    b"AutoCannon", b"autocannon",
    b"DupeMacro", b"Dupe Macro", b"dupemacro",
    b"DupeFinder", b"Dupe Finder", b"dupefinder",
    b"ChunkLoader", b"chunkloader",
    b"SeedCracker", b"Seed Cracker", b"seedcracker",
]

OBFUSCATION_INDICATORS = [
    b"EncryptedString", b"encryptedstring",
    b"StringEncrypter", b"String Encrypter", b"stringencrypter",
    b"StringObfuscator", b"String Obfuscator", b"stringobfuscator",
    b"ClassObfuscator", b"Class Obfuscator", b"classobfuscator",
    b"MethodObfuscator", b"Method Obfuscator", b"methodobfuscator",
    b"FieldObfuscator", b"Field Obfuscator", b"fieldobfuscator",
    b"ZKM", b"ZelixKlassMaster", b"zelixklassmaster",
    b"ProGuard", b"proguard",
    b"allatori", b"Allatori",
    b"DashO", b"dasho",
    b"JShrink", b"jshrink",
    b"RetroGuard", b"retroguard",
    b"JObfuscator", b"jobfuscator",
    b"BinPress", b"binpress",
    b"Stringer", b"stringer-obf",
    b"DexGuard", b"dexguard",
    b"ClassFinalizer", b"classfinalizer",
    b"AntiDecompiler", b"Anti Decompiler", b"antidecompiler",
    b"AntiDebug", b"Anti Debug", b"antidebug",
    b"AntiDump", b"Anti Dump", b"antidump",
    b"AntiTamper", b"Anti Tamper", b"antitamper",
    b"IntegrityCheck", b"Integrity Check", b"integritycheck",
    b"TamperCheck", b"Tamper Check", b"tampercheck",
    b"NativeObfuscator", b"Native Obfuscator", b"nativeobfuscator",
    b"JNIObfuscator", b"JNI Obfuscator", b"jniobfuscator",
    b"NativeWrapper", b"Native Wrapper", b"nativewrapper",
    b"LibraryLoader", b"libraryloader-obf",
    b"JNILoader", b"jniloader-obf",
    b"ObfuscatedName", b"obfuscatedname",
    b"Deobfuscator", b"Deobfuscator", b"deobfuscator",
    b"RuntimeDecryption", b"Runtime Decryption", b"runtimedecryption",
    b"RuntimeDecompiler", b"Runtime Decompiler", b"runtimedecompiler",
    b"ClassTransformer", b"classtransformer-obf",
    b"BytecodeEncryptor", b"Bytecode Encryptor", b"bytecodeencryptor",
    b"BytecodeObfuscator", b"Bytecode Obfuscator", b"bytecodeobfuscator",
    b"CodeEncryption", b"Code Encryption", b"codeencryption",
    b"CodeVirtualization", b"Code Virtualization", b"codevirtualization",
    b"ControlFlowObfuscation", b"Control Flow Obfuscation",
    b"ReferenceObfuscation", b"Reference Obfuscation",
    b"NumberObfuscation", b"Number Obfuscation",
    b"ResourceEncryption", b"Resource Encryption",
    b"StringPoolEncryption", b"String Pool Encryption",
    b"ReflectionObfuscation", b"Reflection Obfuscation",
    b"InvokeDynamic", b"invokedynamic-obf",
    b"LambdaFactory", b"lambdafactory-obf",
    b"HiddenClass", b"hiddenclass-obf",
    b"MethodHandle", b"methodhandle-obf",
    b"VarHandle", b"varhandle-obf",
    b"UnsafeAccess", b"unsafeaccess-obf",
    b"sun.misc.Unsafe", b"sun/misc/Unsafe",
    b"FieldAccessor", b"fieldaccessor-obf",
    b"ReflectionAccess", b"reflectionaccess-obf",
    b"setAccessible", b"setAccessible-obf",
    b"getDeclaredField", b"getDeclaredField-obf",
    b"ClassLoaderHack", b"ClassLoader Hack", b"classloaderhack",
    b"CustomClassLoader", b"Custom ClassLoader", b"customclassloader",
    b"ModuleHack", b"Module Hack", b"modulehack",
    b"AddOpensHack", b"Add Opens Hack", b"addopenshack",
    b"AddExportsHack", b"Add Exports Hack", b"addexportshack",
    b"JVMHack", b"JVM Hack", b"jvmhack",
    b"UnsafeFieldOffset", b"unsafefieldoffset",
    b"UnsafePutLong", b"unsafeputlong",
    b"UnsafeGetObject", b"unsafegetobject",
    b"UnsafeAllocateInstance", b"unsafeallocateinstance",
    b"ReflectionHack", b"Reflection Hack", b"reflectionhack",
]

MIXIN_BYTECODE_PATTERNS = [
    b"org.spongepowered.asm.mixin", b"org/spongepowered/asm/mixin",
    b"MixinMinecraftClient", b"mixinminecraftclient",
    b"MixinEntityPlayer", b"mixinentityplayer",
    b"MixinC06PacketPlayer", b"mixinpacketplayer",
    b"MixinNetworkManager", b"mixinnetworkmanager",
    b"MixinRenderManager", b"mixinrendermanager",
    b"MixinPlayerControllerMP", b"mixinplayercontroller",
    b"MixinEntityRenderer", b"mixinentityrenderer",
    b"MixinBlock", b"mixinblock",
    b"MixinItemStack", b"mixinitemstack",
    b"MixinWorld", b"mixinworld",
    b"MixinChunk", b"mixinchunk",
    b"MixinTileEntity", b"mixintileentity",
    b"MixinGuiScreen", b"mixinguiscreen",
    b"MixinGuiIngame", b"mixinguiingame",
    b"@Inject", b"@Redirect", b"@ModifyArg", b"@ModifyArgs",
    b"@ModifyConstant", b"@ModifyVariable", b"@At",
    b"MixinConnector", b"mixinconnector",
    b"IMixin", b"imixin",
    b"MixinTransformer", b"mixintransformer",
    b"MixinBootstrap", b"mixinbootstrap",
    b"MixinPlatformAgent", b"mixinplatformagent",
    b"MixinConfig", b"mixinconfig",
    b"MixinEnvironment", b"mixinenvironment",
    b"MixinService", b"mixinservice",
    b"MixinApplicator", b"mixinapplicator",
    b"IClassTransformer", b"classtransformer-mixin",
    b"TransformingClassLoader", b"transformingclassloader",
    b"LaunchClassLoader", b"launchclassloader",
    b"net.minecraftforge.fml.common.asm", b"fmlcommonasm",
    b" FMLCorePlugin", b"fmlcoreplugin",
    b"coremodlocation", b"coremod",
    b"IFMLLoadingPlugin", b"ifmlloadingplugin",
    b"ModClassLoader", b"modclassloader",
    b"ModTransformer", b"modtransformer",
    b"AccessTransformer", b"accesstransformer",
    b"deobfTransformer", b"deobftransformer",
    b"ClassPatchManager", b"classpatchmanager",
    b"PatchTransformer", b"patchtransformer",
]

EVENT_BUS_PATTERNS = [
    b"EventBus", b"eventbus",
    b"EventManager", b"eventmanager",
    b"@Subscribe", b"@EventHandler", b"@EventListener",
    b"onMotion", b"onPacket", b"onTick", b"onUpdate",
    b"onRender", b"onRender2D", b"onRender3D",
    b"onAttack", b"onBlockBreak", b"onBlockPlace",
    b"onChat", b"onDeath", b"onJoin", b"onQuit",
    b"onDamage", b"onHeal", b"onTeleport",
    b"onMove", b"onJump", b"onFall", b"onLand",
    b"onUseItem", b"onInteract", b"onEntityUse",
    b"onPacketSend", b"onPacketReceive",
    b"onKeyInput", b"onMouseInput",
    b"onWorldLoad", b"onWorldUnload",
    b"onConnect", b"onDisconnect",
    b"onPlayerAttack", b"onPlayerDeath",
    b"onEntitySpawn", b"onEntityDespawn",
    b"onBlockUpdate", b"onChunkLoad",
    b"PreMotionEvent", b"premotionevent",
    b"PostMotionEvent", b"postmotionevent",
    b"MotionEvent", b"motionevent",
    b"PacketEvent", b"packetevent",
    b"RenderEvent", b"renderevent",
    b"TickEvent", b"tickevent",
    b"UpdateEvent", b"updateevent",
    b"KeyEvent", b"keyevent",
    b"AttackEvent", b"attackevent",
    b"BlockBreakEvent", b"blockbreakevent",
    b"BlockPlaceEvent", b"blockplaceevent",
    b"ChatEvent", b"chatevent",
    b"DamageEvent", b"damageevent",
    b"DeathEvent", b"deathevent",
    b"MoveEvent", b"moveevent",
    b"InteractEvent", b"interactevent",
    b"ConnectEvent", b"connectevent",
    b"DisconnectEvent", b"disconnectevent",
    b"PlayerAttackEvent", b"playerattackevent",
    b"EntitySpawnEvent", b"entityspawnevent",
]

ROTATION_AIM_PATTERNS = [
    b"RotationManager", b"rotationmanager",
    b"RotatorManager", b"rotatormanager",
    b"SilentRotation", b"silentrotation",
    b"RotationHack", b"rotationhack",
    b"AimProcessor", b"aimprocessor",
    b"RotationProcessor", b"rotationprocessor",
    b"TargetProcessor", b"targetprocessor",
    b"RotationUtil", b"rotationutil",
    b"RotationHelper", b"rotationhelper",
    b"AimHelper", b"aimhelper",
    b"TargetHelper", b"targethelper",
    b"FaceTarget", b"facetarget",
    b"FaceEntity", b"faceentity",
    b"FaceBlock", b"faceblock",
    b"LookTarget", b"looktarget",
    b"SetRotation", b"setrotation",
    b"GetRotation", b"getrotation",
    b"RotationVector", b"rotationvector",
    b"YawLock", b"yawlock",
    b"PitchLock", b"pitchlock",
    b"SilentAim", b"silentaim",
    b"SilentLook", b"silentlook",
    b"RotationSnap", b"rotationsnap",
    b"RotationSmooth", b"rotationsmooth",
    b"RotationLerp", b"rotationlerp",
    b"RotationSlerp", b"rotationslerp",
    b"RotationInterpolate", b"rotationinterpolate",
    b"AngleHelper", b"anglehelper",
    b"AngleCalculator", b"anglecalculator",
    b"DistanceCalc", b"distancecalc",
    b"TargetDistance", b"targetdistance",
    b"PredictMovement", b"predictmovement",
    b"MovementPredict", b"movementpredict",
    b"TargetPredict", b"targetpredict",
    b"VelocityPredict", b"velocitypredict",
    b"PositionPredict", b"positionpredict",
    b"HitPredict", b"hitpredict",
    b"ClickSimulator", b"clicksimulator",
    b"AttackSimulator", b"attacksimulator",
]

PACKET_MANIPULATION_PATTERNS = [
    b"PacketSend", b"packetsend",
    b"PacketReceive", b"packetreceive",
    b"PacketCancel", b"packetcancel",
    b"PacketModify", b"packetmodify",
    b"PacketEvent", b"packetevent",
    b"PacketInterceptor", b"packetinterceptor",
    b"PacketHandler", b"packethandler",
    b"PacketManager", b"packetmanager",
    b"PacketUtil", b"packetutil",
    b"PacketHelper", b"packethelper",
    b"PacketSpoof", b"packetspoof",
    b"PacketDelay", b"packetdelay",
    b"PacketDrop", b"packetdrop",
    b"PacketQueue", b"packetqueue",
    b"PacketBuffer", b"packetbuffer",
    b"PacketEncoder", b"packetencoder",
    b"PacketDecoder", b"packetdecoder",
    b"PacketSerializer", b"packetserializer",
    b"PacketDeserializer", b"packetdeserializer",
    b"SendPacket", b"sendpacket",
    b"ReceivePacket", b"receivepacket",
    b"CancelPacket", b"cancelpacket",
    b"ModifyPacket", b"modifypacket",
    b"InjectPacket", b"injectpacket",
    b"ChannelHandler", b"channelhandler",
    b"ChannelInterceptor", b"channelinterceptor",
    b"ChannelPipeline", b"channelpipeline",
    b"NettyInterceptor", b"nettyinterceptor",
    b"NetworkManager", b"networkmanager-hack",
    b"ConnectionMixin", b"connectionmixin",
    b"ClientConnection", b"clientconnection-hack",
    b"PacketC00", b"PacketC01", b"PacketC02", b"PacketC03",
    b"PacketC04", b"PacketC05", b"PacketC06",
    b"PacketC07", b"PacketC08", b"PacketC09",
    b"PacketC0A", b"PacketC0B", b"PacketC0C",
    b"PacketC0D", b"PacketC0E", b"PacketC0F",
    b"PacketC10", b"PacketC11", b"PacketC12",
    b"PacketC13", b"PacketC14", b"PacketC15",
    b"PacketC16", b"PacketC17",
    b"PacketS00", b"PacketS01", b"PacketS02", b"PacketS03",
    b"PacketS04", b"PacketS05", b"PacketS06",
    b"PacketS07", b"PacketS08", b"PacketS09",
    b"PacketS0A", b"PacketS0B", b"PacketS0C",
    b"PacketS0D", b"PacketS0E", b"PacketS0F",
    b"PacketS10", b"PacketS12", b"PacketS13",
    b"PacketS14", b"PacketS15", b"PacketS16",
    b"PacketS17", b"PacketS18", b"PacketS19",
    b"PacketS1A", b"PacketS1B", b"PacketS1C",
    b"PacketS1D", b"PacketS1E", b"PacketS1F",
    b"PacketS20", b"PacketS21", b"PacketS22",
    b"PacketS23", b"PacketS24", b"PacketS25",
    b"PacketS26", b"PacketS27", b"PacketS28",
    b"PacketS29", b"PacketS2A", b"PacketS2B",
    b"PacketS2C", b"PacketS2D", b"PacketS2E",
    b"PacketS2F", b"PacketS30", b"PacketS31",
    b"PacketS32", b"PacketS33", b"PacketS34",
    b"PacketS35", b"PacketS36", b"PacketS37",
    b"PacketS38", b"PacketS39", b"PacketS3A",
    b"PacketS3B", b"PacketS3C", b"PacketS3D",
    b"PacketS3E", b"PacketS3F",
    b"PacketS40", b"PacketS41", b"PacketS42",
    b"PacketS43", b"PacketS44", b"PacketS45",
    b"PacketS46", b"PacketS47", b"PacketS48",
    b"PacketS49", b"PacketS4A", b"PacketS4B",
    b"PacketS4C", b"PacketS4D", b"PacketS4E",
    b"PacketS4F",
]

CONFIG_SETTINGS_PATTERNS = [
    b"modules.json", b"modules-config", b"modulesettings",
    b"settings.json", b"settings-config",
    b"clickgui.json", b"clickgui-config", b"clickguipos",
    b"hud.json", b"hud-config", b"hudsettings",
    b"bindManager", b"bindmanager",
    b"colorSettings", b"colorsettings",
    b"moduleConfig", b"moduleconfig",
    b"ModuleSettings", b"modulesettings",
    b"ConfigManager", b"configmanager",
    b"SettingsManager", b"settingsmanager",
    b"PreferenceManager", b"preferencemanager",
    b"ConfigLoader", b"configloader",
    b"SettingsLoader", b"settingsloader",
    b"JsonConfig", b"jsonconfig",
    b"YamlConfig", b"yamlconfig",
    b"ConfigSerializer", b"configserializer",
    b"ConfigDeserializer", b"configdeserializer",
    b"SaveConfig", b"saveconfig",
    b"LoadConfig", b"loadconfig",
    b"ResetConfig", b"resetconfig",
    b"DefaultConfig", b"defaultconfig",
    b"ProfileManager", b"profilemanager",
    b"ProfileLoader", b"profileloader",
    b"SaveProfile", b"saveprofile",
    b"LoadProfile", b"loadprofile",
    b"ThemeManager", b"thememanager",
    b"ColorManager", b"colormanager",
    b"FontManager", b"fontmanager",
    b"KeyBindManager", b"keybindmanager",
    b"BindSet", b"bindset",
    b"KeyBinding", b"keybinding-cheat",
    b"ToggleBind", b"togglebind",
    b"BindCommand", b"bindcommand",
]

COMMAND_SYSTEM_PATTERNS = [
    b"CommandManager", b"commandmanager",
    b"CommandBase", b"commandbase",
    b"ChatCommand", b"chatcommand",
    b"PrefixCommand", b"prefixcommand",
    b"CommandProcessor", b"commandprocessor",
    b"CommandDispatcher", b"commanddispatcher",
    b"CommandHandler", b"commandhandler-cheat",
    b"CommandRegistry", b"commandregistry",
    b"CommandExecutor", b"commandexecutor",
    b"AbstractCommand", b"abstractcommand",
    b"CommandAnnotation", b"commandannotation",
    b".toggle", b".bind", b".set", b".config",
    b".friend", b".enemy", b".target",
    b".enable", b".disable", b".toggle",
    b".save", b".load", b".reset",
    b".prefix", b".watermark", b".clientname",
    b".gui", b".clickgui", b".hud",
    b".selfdestruct", b".panic",
    b"CommandPrefix", b"commandprefix",
    b"setPrefix", b"setprefix",
    b"getPrefix", b"getprefix",
    b"ChatListener", b"chatlistener",
    b"ChatProcessor", b"chatprocessor",
    b"MessageHandler", b"messagehandler-cheat",
    b"onChatMessage", b"onchatmessage",
    b"handleCommand", b"handlecommand",
    b"processCommand", b"processcommand",
    b"executeCommand", b"executecommand",
    b"registerCommand", b"registercommand",
    b"unregisterCommand", b"unregistercommand",
    b"CommandList", b"commandlist",
    b"HelpCommand", b"helpcommand",
    b"ToggleCommand", b"togglecommand",
    b"BindCommand", b"bindcommand-cheat",
    b"ConfigCommand", b"configcommand",
    b"FriendCommand", b"friendcommand",
    b"PanicCommand", b"paniccommand",
    b"WatermarkCommand", b"watermarkcommand",
]

HUD_CLICKGUI_PATTERNS = [
    b"ClickGUI", b"ClickGui", b"clickgui",
    b"HUDManager", b"HudManager", b"hudmanager",
    b"DraggableComponent", b"draggablecomponent",
    b"DraggableElement", b"draggableelement",
    b"ModuleButton", b"modulebutton",
    b"CategoryPanel", b"categorypanel",
    b"CategoryButton", b"categorybutton",
    b"ColorPicker", b"colorpicker",
    b"ColorSlider", b"colorslider",
    b"SliderComponent", b"slidercomponent",
    b"CheckBox", b"checkbox-cheat",
    b"ToggleButton", b"togglebutton-cheat",
    b"EnumButton", b"enumbutton",
    b"ModeButton", b"modebutton",
    b"ValueSlider", b"valueslider",
    b"NumberSlider", b"numberslider",
    b"ModulePanel", b"modulepanel",
    b"ModuleList", b"modulelist-gui",
    b"WindowComponent", b"windowcomponent",
    b"FrameComponent", b"framecomponent",
    b"TabComponent", b"tabcomponent",
    b"GuiScreen", b"guiscreen-cheat",
    b"GuiRender", b"guirender",
    b"RenderManager", b"rendermanager-cheat",
    b"DrawManager", b"drawmanager",
    b"RenderHelper", b"renderhelper-cheat",
    b"FontRenderer", b"fontrenderer-cheat",
    b"TextRenderer", b"textrenderer",
    b"RenderUtil", b"renderutil",
    b"DrawUtil", b"drawutil",
    b"ColorUtil", b"colorutil",
    b"GuiUtil", b"guiutil",
    b"ScreenUtil", b"screenutil",
    b"Render2D", b"render2d",
    b"Render3D", b"render3d",
    b"Watermark", b"watermark",
    b"WatermarkRender", b"watermarkrender",
    b"ArrayListRender", b"arraylistrender",
    b"ArrayList", b"arraylist-cheat",
    b"TabGui", b"tabgui",
    b"TabGUI", b"TabGuiRender",
    b"Notifications", b"notifications-cheat",
    b"NotificationManager", b"notificationmanager",
    b"NotificationRender", b"notificationrender",
    b"IngameHUD", b"ingamehud",
    b"HUDRender", b"hudrender",
    b"HUDOverlay", b"hudoverlay",
    b"Keystrokes", b"keystrokes",
    b"KeystrokesRender", b"keystrokesrender",
    b"ArmorHUD", b"armorhud",
    b"PotionHUD", b"potionhud",
    b"Coordinates", b"coordinates-hud",
    b"FPSDisplay", b"fpsdisplay",
    b"CPSCounter", b"cpscounter",
    b"ReachDisplay", b"reachdisplay",
]

FRIEND_SYSTEM_PATTERNS = [
    b"FriendManager", b"friendmanager",
    b"FriendList", b"friendlist",
    b"FriendCommand", b"friendcommand",
    b"isFriend", b"isfriend",
    b"addFriend", b"addfriend",
    b"removeFriend", b"removefriend",
    b"getFriends", b"getfriends",
    b"FriendEntry", b"friendentry",
    b"FriendData", b"frienddata",
    b"EnemyManager", b"enemymanager",
    b"EnemyList", b"enemylist",
    b"isEnemy", b"isenemy",
    b"addEnemy", b"addenemy",
    b"removeEnemy", b"removeenemy",
    b"TargetManager", b"targetmanager",
    b"TargetList", b"targetlist",
    b"isTarget", b"istarget",
    b"addTarget", b"addtarget",
    b"removeTarget", b"removetarget",
    b"getTargets", b"gettargets",
    b"TeamManager", b"teammanager",
    b"isTeammate", b"isteammate",
    b"getTeam", b"getteam",
    b"SortFriends", b"sortfriends",
    b"FriendComparator", b"friendcomparator",
    b"FriendSerializer", b"friendserializer",
    b"FriendDeserializer", b"frienddeserializer",
    b"saveFriends", b"savefriends",
    b"loadFriends", b"loadfriends",
    b"friendFile", b"friendfile",
    b"friends.json", b"enemies.json",
    b"targets.json",
]

CHEAT_MODULE_CATEGORIES = {
    "COMBAT": CHEAT_MODULES_COMBAT,
    "CRYSTAL_ANCHOR": CHEAT_MODULES_CRYSTAL_ANCHOR,
    "TOTEM": CHEAT_MODULES_TOTEM,
    "MOVEMENT": CHEAT_MODULES_MOVEMENT,
    "UTILITY_AUTOMATION": CHEAT_MODULES_UTILITY,
    "ESP_VISION": CHEAT_MODULES_ESP_VISION,
    "EVASION_BYPASS": CHEAT_MODULES_EVASION,
    "WORLD_FINDER": CHEAT_MODULES_WORLD,
}

CHEAT_MODULES = []
for _cat_modules in CHEAT_MODULE_CATEGORIES.values():
    CHEAT_MODULES.extend(_cat_modules)

MINECRAFT_IDENTIFIERS = [
    b"net.minecraft", b"net/minecraft",
    b"com.mojang", b"com/mojang",
    b"org.lwjgl", b"org/lwjgl",
    b"Minecraft", b"minecraft",
    b"Minecraft.jar", b"minecraft.jar",
    b"MinecraftClient", b"minecraft-client",
    b"net.minecraft.client.main.Main",
    b"net.minecraft.client.Minecraft",
    b"com.mojang.blaze3d",
    b"com.mojang.authlib",
    b"com.mojang.brigadier",
    b"cpw.mods", b"net.minecraftforge",
    b"net.fabricmc", b"org.quiltmc",
    b"org.bukkit", b"org.spigotmc",
    b"Minecraft Launch", b"Minecraft Launcher",
    b"Lunar Client", b"Badlion Client",
    b"TLauncher", b"MultiMC",
    b"Prism Launcher", b"ATLauncher",
    b"CurseForge",
]

MOD_LOADER_PATTERNS = [
    b"forge", b"ForgeMod", b"fml.", b"net.minecraftforge",
    b"fabric", b"FabricLoader", b"FabricMod", b"net.fabricmc",
    b"quilt", b"QuiltLoader", b"org.quiltmc",
    b"optifine", b"Optifine", b"OptiFine",
    b"rift", b"RiftMod",
    b"liteloader", b"LiteLoader",
    b"risugami", b"ModLoader",
]

CHEAT_INJECTORS = [
    b"Agent-Class",
    b"loadAgent",
    b"com.sun.tools.attach", b"VirtualMachine.attach", b"attachVirtualMachine",
    b"ByteBuddyAgent",
]

CHEAT_CONFIG_SIGNATURES = [
    b"clickgui.json", b"modules.json", b"hud.json",
    b"enabledModules", b"enabled_modules",
    b"\\cheats\\", b"/cheats/", b"\\hacks\\", b"/hacks/",
    b"cheat.cfg", b"baritone.settings",
    b"altmanager", b"AltManager", b"alt-manager",
    b"sessionstealer", b"session-stealer", b"SessionStealer",
]

ALL_SCAN_CATEGORIES = {
    "INJECTION_API_PROCESS": INJECTION_API_PROCESS,
    "INJECTION_API_WINDOW": INJECTION_API_WINDOW,
    "INJECTION_API_MEMORY": INJECTION_API_MEMORY,
    "INJECTION_API_EXEC": INJECTION_API_EXEC,
    "INJECTION_API_MISC": INJECTION_API_MISC,
    "CHEAT_CLIENT": CHEAT_CLIENTS,
    "CHEAT_MODULE_COMBAT": CHEAT_MODULES_COMBAT,
    "CHEAT_MODULE_CRYSTAL_ANCHOR": CHEAT_MODULES_CRYSTAL_ANCHOR,
    "CHEAT_MODULE_TOTEM": CHEAT_MODULES_TOTEM,
    "CHEAT_MODULE_MOVEMENT": CHEAT_MODULES_MOVEMENT,
    "CHEAT_MODULE_UTILITY": CHEAT_MODULES_UTILITY,
    "CHEAT_MODULE_ESP_VISION": CHEAT_MODULES_ESP_VISION,
    "CHEAT_MODULE_EVASION": CHEAT_MODULES_EVASION,
    "CHEAT_MODULE_WORLD": CHEAT_MODULES_WORLD,
    "OBFUSCATION": OBFUSCATION_INDICATORS,
    "MIXIN_BYTECODE": MIXIN_BYTECODE_PATTERNS,
    "EVENT_BUS": EVENT_BUS_PATTERNS,
    "ROTATION_AIM": ROTATION_AIM_PATTERNS,
    "PACKET_MANIPULATION": PACKET_MANIPULATION_PATTERNS,
    "CONFIG_SETTINGS": CONFIG_SETTINGS_PATTERNS,
    "COMMAND_SYSTEM": COMMAND_SYSTEM_PATTERNS,
    "HUD_CLICKGUI": HUD_CLICKGUI_PATTERNS,
    "FRIEND_SYSTEM": FRIEND_SYSTEM_PATTERNS,
    "CHEAT_INJECTOR": CHEAT_INJECTORS,
    "CHEAT_CONFIG": CHEAT_CONFIG_SIGNATURES,
    "MINECRAFT_IDENTIFIER": MINECRAFT_IDENTIFIERS,
    "MOD_LOADER": MOD_LOADER_PATTERNS,
}

CHEAT_MODULE_CATEGORY_MAP = {
    "CHEAT_MODULE_COMBAT": "Combat",
    "CHEAT_MODULE_CRYSTAL_ANCHOR": "Crystal / Anchor PvP",
    "CHEAT_MODULE_TOTEM": "Totem",
    "CHEAT_MODULE_MOVEMENT": "Movement",
    "CHEAT_MODULE_UTILITY": "Utility / Automation",
    "CHEAT_MODULE_ESP_VISION": "ESP / Vision",
    "CHEAT_MODULE_EVASION": "Evasion / Anticheat Bypass",
    "CHEAT_MODULE_WORLD": "World / Finder",
}

ALL_CHEAT_MODULE_SCAN_CATS = list(CHEAT_MODULE_CATEGORY_MAP.keys())

_PATTERN_TO_CATEGORY = {}
_ALL_PATTERNS = []
for _cat, _pats in ALL_SCAN_CATEGORIES.items():
    for _p in _pats:
        _PATTERN_TO_CATEGORY.setdefault(_p, []).append(_cat)
        _ALL_PATTERNS.append(_p)

_UNIQUE_PATTERNS = sorted(set(_ALL_PATTERNS), key=len, reverse=True)
_COMBINED_PATTERN_RE = re.compile(b'|'.join(re.escape(p) for p in _UNIQUE_PATTERNS))


def _is_word_byte(b):
    return (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b == 95


def _boundary_ok(matched, data, start, end):
    if _is_word_byte(matched[0]) and start > 0 and _is_word_byte(data[start - 1]):
        return False
    if _is_word_byte(matched[-1]) and end < len(data) and _is_word_byte(data[end]):
        return False
    return True


_STRING_KEYWORDS = frozenset([
    "killaura", "aimbot", "triggerbot", "autoclicker",
    "autocrystal", "crystalaura", "maceaura", "macespam", "macecombo",
    "silentaim", "aimassist", "autototem", "totemoffhand",
    "noclip", "freecam", "fastplace",
    "xray", "wallhack", "nofall", "antiknockback",
    "packetfly", "flyhack", "speedhack", "reachhack", "blockreach",
    "selfdestruct", "self-destruct", "stringcleaner", "string cleaner",
    "antisstool", "anti ss", "antiscreenshare", "screenshare bypass",
    "processhider", "antiforensics", "wipetraces", "prefetchcleaner",
    "pingspoof", "packspoof", "fakelag",
    "straybypass", "donutsmp bypass", "cwcrystal", "marlowanchor",
    "anchorexploder", "cordsnapper", "keypearl", "autorestock",
    "cheststealer", "autopearl", "pearlaura", "automend",
    "virtualmachine.attach", "com.sun.tools.attach",
    "clickgui", "altmanager", "sessionstealer", "enabledmodules",
    "wurst", "meteor-client", "meteorclient", "impactclient",
    "rusherhack", "liquidbounce", "novoline", "baritone",
    "doomsday", "doomsdayclient", "doomsday-client", "doomsdayclient.xyz",
    "doomsdayhack", "doomsdayinject", "doomsdayloader",
    "doomsdayselfdestruct", "doomsdaycleaner", "doomsdaybypass",
    "hitboxes", "hitbox", "jumpreset", "autojumpreset",
    "blockesp", "esp", "strafe", "velocity",
    "shieldbreaker", "hud", "tracers", "playereesp", "storageesp",
    "autoarmor", "wtap", "safewalk", "antiinvis", "itemesp",
    "nametags", "reach", "autototem",
    "dev.lvstrng.argon", "argonclient", "argon-client", "lvstrng",
    "encryptedstring", "selfdestruct.destruct", "memory.purge", "memory.disposeall",
    "anchormacro", "nomissdelay", "nobounce", "prevent", "autopotrefill",
    "automace", "stunslam", "maceswap", "safeanchor", "safecart",
    "tunnelbasefinder", "lightfinder", "lightesp", "lightdebug",
    "fakescoreboard", "donut",
    "encryptedstring", "stringobfuscator", "bytecodeobfuscator",
    "antidecompiler", "antidebug", "antidump", "antitamper",
    "runtimeencryption", "codevirtualization", "nativeobfuscator",
    "reflectionhack", "classloaderhack", "jvmhack",
    "spongepowered.mixin", "mixintransformer", "launchclassloader",
    "iclasstransformer", "premotionevent", "postmotionevent",
    "rotationmanager", "silentrotation", "aimprocessor",
    "packetinterceptor", "packetcancel", "packetspoof",
    "configmanager", "settingsmanager", "clickgui",
    "commandmanager", "commandprefix", "paniccommand",
    "hudmanager", "watermark", "arraylistrender", "tabgui",
    "friendmanager", "friendlist", "enemymanager",
])

_KW_SORTED = sorted(_STRING_KEYWORDS, key=len, reverse=True)
_ASCII_KW_RE = re.compile(
    b'|'.join(re.escape(k.encode("ascii")) for k in _KW_SORTED), re.IGNORECASE
)
_UTF16_KW_RE = re.compile(
    b'|'.join(re.escape(k.encode("utf-16-le")) for k in _KW_SORTED), re.IGNORECASE
)


JAVA_PROCESS_NAMES = {
    "java.exe", "javaw.exe", "javac.exe",
    "jshell.exe", "jcmd.exe", "jps.exe",
}

CHEAT_DOMAIN_PATTERNS = [
    (b"doomsdayclient.com", b"DoomsdayClient"),
    (b"doomsday-client.com", b"DoomsdayClient"),
    (b"doomsday.gg", b"DoomsdayClient"),
    (b"doomsdayclient.net", b"DoomsdayClient"),
    (b"doomsdayclient.org", b"DoomsdayClient"),
    (b"doomsdayclient.xyz", b"DoomsdayClient"),
    (b"vape.gg", b"Vape"),
    (b"vape.llc", b"Vape"),
    (b"impactclient.net", b"Impact"),
    (b"meteorclient.com", b"Meteor"),
    (b"rushershack.com", b"RusherHack"),
    (b"novoline.solutions", b"Novoline"),
    (b"riseclient.com", b"Rise"),
    (b"futureclient.net", b"Future"),
    (b"sigmaclient.info", b"Sigma"),
    (b"aristois.net", b"Aristois"),
    (b"salhack.com", b"Salhack"),
    (b"kamiblue.org", b"KamiBlue"),
    (b"bleachhack.org", b"BleachHack"),
    (b"thunderhack.net", b"Thunderhack"),
    (b"zerodayclient.com", b"ZeroDay"),
]

_DOMAIN_PATTERN_RE = re.compile(b'|'.join(re.escape(d) for d, _ in CHEAT_DOMAIN_PATTERNS))
_DOMAIN_TO_CLIENT = {d: c for d, c in CHEAT_DOMAIN_PATTERNS}


_PAT_AUTO = None
_KW_AUTO = None

if _HAVE_AC:
    _PAT_AUTO = ahocorasick.Automaton()
    for _p in _UNIQUE_PATTERNS:
        _PAT_AUTO.add_word(_p.decode("latin-1"), ("P", _p))
    for _dom, _client in CHEAT_DOMAIN_PATTERNS:
        _PAT_AUTO.add_word(_dom.decode("latin-1"), ("D", _client, len(_dom)))
    _PAT_AUTO.make_automaton()

    _KW_AUTO = ahocorasick.Automaton()
    for _kw in _STRING_KEYWORDS:
        _a = _kw.lower()
        _KW_AUTO.add_word(_a, ("A", len(_a)))
        _u = _kw.encode("utf-16-le").decode("latin-1").lower()
        _KW_AUTO.add_word(_u, ("U", len(_u)))
    _KW_AUTO.make_automaton()


def _context_str(data, start, length):
    a = max(0, start - 48)
    b = min(len(data), start + length + 48)
    s = data[a:b].decode("latin-1", "replace")
    return re.sub(r'[^\x20-\x7E]+', ' ', s).strip()[:200]


def _scan_region_ac(result, data, address):
    n = len(data)
    text = data.decode("latin-1")
    seen_p = result._seen_pattern_keys
    pcounts = result._pat_counts

    for end_idx, val in _PAT_AUTO.iter(text):
        if result.pattern_hits >= MAX_FOUND_PATTERNS:
            break
        if val[0] == "P":
            p = val[1]
            if pcounts.get(p, 0) >= PER_PATTERN_CAP:
                continue
            ln = len(p)
            start = end_idx - ln + 1
            if not _boundary_ok(p, data, start, end_idx + 1):
                continue
            key = (p, address + start)
            if key in seen_p:
                continue
            seen_p.add(key)
            pcounts[p] = pcounts.get(p, 0) + 1
            result.pattern_hits += 1
            rec = {
                "pattern": p.decode("latin-1"),
                "address": f"0x{address + start:016X}",
                "context": _context_str(data, start, ln),
            }
            for cat in _PATTERN_TO_CATEGORY.get(p, ()):
                result.found_patterns[cat].append(rec)
        else:
            client = val[1]
            ln = val[2]
            start = end_idx - ln + 1
            key = (b"DOM:" + client, address + start)
            if key in seen_p:
                continue
            seen_p.add(key)
            result.pattern_hits += 1
            result.found_patterns["CHEAT_CLIENT"].append({
                "pattern": client.decode("latin-1"),
                "address": f"0x{address + start:016X}",
                "context": f"[DOMAIN] {_context_str(data, start, ln)}",
            })

    if len(result.found_strings) >= MAX_FOUND_STRINGS:
        return
    seen_s = result._seen_string_keys
    low = text.lower()
    for end_idx, val in _KW_AUTO.iter(low):
        typ, ln = val
        start = end_idx - ln + 1
        if typ == "A":
            sstart = start
            while sstart > 0 and 0x20 <= data[sstart - 1] <= 0x7E:
                sstart -= 1
            send = end_idx + 1
            while send < n and 0x20 <= data[send] <= 0x7E:
                send += 1
            s = data[sstart:send].decode("ascii", "replace")
            enc = "ascii"
        else:
            sstart = start
            while sstart - 2 >= 0 and 0x20 <= data[sstart - 2] <= 0x7E and data[sstart - 1] == 0:
                sstart -= 2
            send = end_idx + 1
            while send + 1 < n and 0x20 <= data[send] <= 0x7E and data[send + 1] == 0:
                send += 2
            s = data[sstart:send].decode("utf-16-le", "replace")
            enc = "utf-16"
        s_key = (s, address + sstart)
        if s_key in seen_s:
            continue
        seen_s.add(s_key)
        result.found_strings.append({
            "string": s[:200],
            "address": f"0x{address + sstart:016X}",
            "encoding": enc,
        })
        if len(result.found_strings) >= MAX_FOUND_STRINGS:
            break


def _scan_region_regex(result, data, address):
    n = len(data)
    pcounts = result._pat_counts
    for m in _COMBINED_PATTERN_RE.finditer(data):
        if result.pattern_hits >= MAX_FOUND_PATTERNS:
            break
        matched = m.group()
        if pcounts.get(matched, 0) >= PER_PATTERN_CAP:
            continue
        pos = m.start()
        if not _boundary_ok(matched, data, pos, m.end()):
            continue
        found_key = (matched, address + pos)
        if found_key in result._seen_pattern_keys:
            continue
        result._seen_pattern_keys.add(found_key)
        pcounts[matched] = pcounts.get(matched, 0) + 1
        result.pattern_hits += 1
        for cat in _PATTERN_TO_CATEGORY.get(matched, []):
            result.found_patterns[cat].append({
                "pattern": matched.decode("latin-1"),
                "address": f"0x{address + pos:016X}",
                "context": _context_str(data, pos, len(matched)),
            })

    for dm in _DOMAIN_PATTERN_RE.finditer(data):
        matched_domain = dm.group()
        pos = dm.start()
        found_key = (matched_domain, address + pos)
        if found_key in result._seen_pattern_keys:
            continue
        result._seen_pattern_keys.add(found_key)
        result.pattern_hits += 1
        client_name = _DOMAIN_TO_CLIENT.get(matched_domain, b"Unknown")
        result.found_patterns["CHEAT_CLIENT"].append({
            "pattern": client_name.decode("latin-1"),
            "address": f"0x{address + pos:016X}",
            "context": f"[DOMAIN] {_context_str(data, pos, len(matched_domain))}",
        })

    if len(result.found_strings) < MAX_FOUND_STRINGS:
        for km in _ASCII_KW_RE.finditer(data):
            sstart = km.start()
            while sstart > 0 and 0x20 <= data[sstart - 1] <= 0x7E:
                sstart -= 1
            send = km.end()
            while send < n and 0x20 <= data[send] <= 0x7E:
                send += 1
            s = data[sstart:send].decode("ascii", "replace")
            s_key = (s, address + sstart)
            if s_key in result._seen_string_keys:
                continue
            result._seen_string_keys.add(s_key)
            result.found_strings.append({
                "string": s[:200],
                "address": f"0x{address + sstart:016X}",
                "encoding": "ascii",
            })
            if len(result.found_strings) >= MAX_FOUND_STRINGS:
                break

    if len(result.found_strings) < MAX_FOUND_STRINGS:
        for km in _UTF16_KW_RE.finditer(data):
            sstart = km.start()
            while sstart - 2 >= 0 and 0x20 <= data[sstart - 2] <= 0x7E and data[sstart - 1] == 0:
                sstart -= 2
            send = km.end()
            while send + 1 < n and 0x20 <= data[send] <= 0x7E and data[send + 1] == 0:
                send += 2
            s = data[sstart:send].decode("utf-16-le", "replace")
            s_key = (s, address + sstart)
            if s_key in result._seen_string_keys:
                continue
            result._seen_string_keys.add(s_key)
            result.found_strings.append({
                "string": s[:200],
                "address": f"0x{address + sstart:016X}",
                "encoding": "utf-16",
            })
            if len(result.found_strings) >= MAX_FOUND_STRINGS:
                break


def find_java_processes():
    results = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
        try:
            name = (proc.info["name"] or "").lower()
            cmdline = proc.info["cmdline"] or []
            cmdline_str = " ".join(cmdline).lower()
            exe = proc.info["exe"] or ""

            if name not in JAVA_PROCESS_NAMES:
                continue

            mc_type = None
            mc_version = None

            if "minecraft" in cmdline_str or "net.minecraft" in cmdline_str:
                mc_type = "minecraft"
            elif "lunar" in cmdline_str:
                mc_type = "lunar"
            elif "badlion" in cmdline_str:
                mc_type = "badlion"
            elif "forge" in cmdline_str or "fml" in cmdline_str:
                mc_type = "forge"
            elif "fabric" in cmdline_str or "fabricmc" in cmdline_str:
                mc_type = "fabric"
            elif "quilt" in cmdline_str or "quiltmc" in cmdline_str:
                mc_type = "quilt"
            elif "optifine" in cmdline_str or "optifabric" in cmdline_str:
                mc_type = "optifine"
            elif "tlauncher" in cmdline_str:
                mc_type = "tlauncher"
            elif any(ident.decode("latin-1").lower() in cmdline_str
                     for ident in [b"net.minecraft", b"com.mojang", b"org.lwjgl"]):
                mc_type = "minecraft"
            else:
                title = get_window_title_for_pid(proc.info["pid"])
                if title and ("minecraft" in title.lower() or "lunar" in title.lower()
                              or "badlion" in title.lower()):
                    mc_type = "window-detected"

            if mc_type is None:
                continue

            for arg in cmdline:
                arg_l = arg.lower()
                if "--version" in arg_l:
                    idx = cmdline.index(arg)
                    if idx + 1 < len(cmdline):
                        mc_version = cmdline[idx + 1]
            if not mc_version:
                for arg in cmdline:
                    if re.search(r'\b1\.\d+\.\d+', arg):
                        mc_version = arg
                        break

            results.append({
                "pid": proc.info["pid"],
                "name": proc.info["name"],
                "exe": exe,
                "cmdline": cmdline,
                "cmdline_str": " ".join(cmdline),
                "mc_type": mc_type,
                "mc_version": mc_version,
                "create_time": datetime.datetime.fromtimestamp(
                    proc.info["create_time"]
                ).isoformat() if proc.info["create_time"] else None,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


def get_window_title_for_pid(pid):
    found_titles = []

    def enum_callback(hwnd, _):
        pid_wnd = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_wnd))
        if pid_wnd.value == pid:
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if buf.value:
                    found_titles.append(buf.value)
        return True

    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    user32.EnumWindows(EnumWindowsProc(enum_callback), 0)

    return found_titles[0] if found_titles else None


def scan_modules(pid):
    modules = []

    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if snapshot:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)

        if kernel32.Module32FirstW(snapshot, ctypes.byref(me)):
            while True:
                mod_name = me.szModule
                mod_path = me.szExePath
                base_addr = me.modBaseAddr if me.modBaseAddr else 0
                base_size = me.modBaseSize

                mod_info = {
                    "name": mod_name,
                    "path": mod_path,
                    "base": f"0x{base_addr:016X}" if base_addr else "0x0",
                    "size": base_size,
                }
                modules.append(mod_info)

                if not kernel32.Module32NextW(snapshot, ctypes.byref(me)):
                    break
        kernel32.CloseHandle(snapshot)

    if not modules:
        try:
            proc = psutil.Process(pid)
            for mmap in proc.memory_maps(grouped=False):
                path = mmap.path
                if not path or path.startswith("[") or path.startswith("/"):
                    continue
                mod_name = os.path.basename(path)
                mod_info = {
                    "name": mod_name,
                    "path": path,
                    "base": f"0x{mmap.addr.split('-')[0]:016X}" if '-' in mmap.addr else "0x0",
                    "size": 0,
                }
                modules.append(mod_info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return modules, []


class MemoryScanResult:
    def __init__(self):
        self.found_patterns = defaultdict(list)
        self.found_strings = []
        self.scan_count = 0
        self.regions_scanned = 0
        self.total_bytes_scanned = 0
        self.errors = []
        self.pattern_hits = 0
        self._pat_counts = {}
        self._seen_pattern_keys = set()
        self._seen_string_keys = set()


_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _fmt_time(secs):
    secs = max(0, int(secs))
    if secs < 60:
        return f"{secs}s"
    return f"{secs // 60}m{secs % 60:02d}s"


def _draw_progress(processed, planned, start_time, spin_idx, found):
    planned = max(planned, 1)
    frac = min(1.0, processed / planned)
    width = 30
    filled = int(width * frac)
    bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"
    pct = frac * 100.0
    elapsed = time.time() - start_time
    eta = (elapsed / frac - elapsed) if frac > 1e-6 else 0.0
    spin = _SPINNER[spin_idx % len(_SPINNER)]
    mb = processed / 1048576.0
    flag = f"  {RED}flags:{found}{RESET}" if found else ""
    sys.stdout.write(
        f"\r  {CYAN}{spin}{RESET} {BOLD}Scanning{RESET} {bar} "
        f"{BOLD}{pct:5.1f}%{RESET} {DIM}{mb:6.1f}MB  ETA {_fmt_time(eta):>5}{RESET}{flag}   "
    )
    sys.stdout.flush()


def _finish_progress(processed, planned, start_time, found, partial=False):
    elapsed = time.time() - start_time
    planned = max(planned or processed, 1)
    frac = min(1.0, processed / planned)
    width = 30
    filled = int(width * frac)
    bar = f"{GREEN}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"
    pct = frac * 100.0
    mb = processed / 1048576.0
    if partial:
        label = f"{YELLOW}■ Partial{RESET} "
        flag = f"  {YELLOW}stopped (time limit){RESET}"
    else:
        label = f"{GREEN}✓{RESET} {BOLD}Done{RESET}    "
        flag = f"  {RED}flags:{found}{RESET}" if found else f"  {GREEN}clean{RESET}"
    sys.stdout.write(
        f"\r  {label} {bar} {BOLD}{pct:5.1f}%{RESET} "
        f"{DIM}{mb:6.1f}MB in {_fmt_time(elapsed):>5}{RESET}{flag}        \n"
    )
    sys.stdout.flush()


def _estimate_scan_total(handle, deep):
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    planned = 0
    while address < MAX_ADDRESS:
        if kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ) == 0:
            break
        is_committed = mbi.State == MEM_COMMIT
        is_not_guarded = not (mbi.Protect & PAGE_GUARD)
        if deep:
            ok = is_committed and is_not_guarded and mbi.Protect != PAGE_NOACCESS
        else:
            ok = is_committed and mbi.Protect in WRITABLE_PROTECTIONS and is_not_guarded
        if ok:
            planned += min(mbi.RegionSize, MAX_REGION_SIZE)
            if planned >= MAX_TOTAL_SCAN:
                return MAX_TOTAL_SCAN
        if mbi.RegionSize == 0:
            break
        address += mbi.RegionSize
    return planned


def scan_process_memory(pid, verbose=False, deep=False, show_progress=False, time_budget=MAX_SCAN_SECONDS):
    result = MemoryScanResult()

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid,
    )
    if not handle:
        err = ctypes.GetLastError()
        result.errors.append(
            f"OpenProcess failed (error={err}). "
            f"Admin rights required for memory reading."
        )
        return result

    result.scan_count = 1
    planned_total = _estimate_scan_total(handle, deep) if show_progress else 0
    start_time = time.time()
    last_render = 0.0
    spin_idx = 0

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    total_scanned = 0
    region_count = 0
    partial = False

    while address < MAX_ADDRESS:
        if time_budget and time.time() - start_time > time_budget:
            partial = True
            result.errors.append(
                f"Time budget reached ({time_budget}s) - partial scan "
                f"({total_scanned // 1048576}MB)"
            )
            break

        if kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        ) == 0:
            break

        is_committed = mbi.State == MEM_COMMIT
        is_not_guarded = not (mbi.Protect & PAGE_GUARD)

        if deep:
            should_scan = is_committed and is_not_guarded and mbi.Protect != PAGE_NOACCESS
        else:
            should_scan = is_committed and mbi.Protect in WRITABLE_PROTECTIONS and is_not_guarded

        if should_scan:
            region_size = min(mbi.RegionSize, MAX_REGION_SIZE)

            if total_scanned + region_size > MAX_TOTAL_SCAN:
                region_size = MAX_TOTAL_SCAN - total_scanned
                if region_size <= 0:
                    break

            try:
                buf = (ctypes.c_ubyte * region_size)()
                bytes_read = ctypes.c_size_t(0)

                if kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(address),
                    buf,
                    region_size,
                    ctypes.byref(bytes_read),
                ):
                    data = bytes(buf[:bytes_read.value])
                    result.regions_scanned += 1
                    result.total_bytes_scanned += len(data)
                    total_scanned += len(data)
                    region_count += 1

                    if show_progress:
                        now = time.time()
                        if now - last_render >= 0.08:
                            found = sum(len(v) for v in result.found_patterns.values())
                            _draw_progress(total_scanned, planned_total, start_time, spin_idx, found)
                            spin_idx += 1
                            last_render = now

                    if _HAVE_AC:
                        _scan_region_ac(result, data, address)
                    else:
                        _scan_region_regex(result, data, address)

                    if (result.pattern_hits >= MAX_FOUND_PATTERNS
                            and len(result.found_strings) >= MAX_FOUND_STRINGS):
                        result.errors.append(
                            "Stopped early - abundant detections collected"
                        )
                        break

            except Exception:
                pass

        address += mbi.RegionSize
        if mbi.RegionSize == 0:
            break

    kernel32.CloseHandle(handle)

    if show_progress:
        total_found = sum(len(v) for v in result.found_patterns.values())
        _finish_progress(total_scanned, planned_total, start_time, total_found, partial)

    return result


def assess_threat_level(scan_result, suspicious_modules=None, proc_info=None):
    score = 0
    reasons = []

    # Doomsday + Argon override: check for specific client signatures
    all_hits = []
    for cat_hits in scan_result.found_patterns.values():
        all_hits.extend(cat_hits)

    doomsday_active = False
    argon_active = False
    argon_selfdestructed = False

    for h in all_hits:
        ctx = h.get("context", "").lower()
        pat = h.get("pattern", "")
        if isinstance(pat, bytes):
            pat = pat.decode("ascii", "replace")
        pat_l = pat.lower()

        # Doomsday checks
        if "doomsdayclient.xyz" in ctx or "doomsdayclient.xyz" in pat_l:
            doomsday_active = True

        # Argon checks - active if full client strings found
        if "dev.lvstrng.argon" in ctx or "dev.lvstrng.argon" in pat_l:
            argon_active = True
        if "argon.instance" in ctx or "argon.instance" in pat_l:
            argon_active = True
        if "lvstrng" in ctx or "lvstrng" in pat_l:
            argon_active = True
        # Self-destructed: only class skeleton remains, module names nulled
        if "selfdestruct.destruct" in ctx or "selfdestruct.destruct" in pat_l:
            argon_selfdestructed = True
        if "memory.purge" in ctx or "memory.purge" in pat_l:
            argon_selfdestructed = True
        if "memory.disposeall" in ctx or "memory.disposeall" in pat_l:
            argon_selfdestructed = True

    # Check cmdline for theseus.jar (survives self-destruct, Doomsday only)
    theseus_in_cmdline = False
    if proc_info:
        cmdline_str = (proc_info.get("cmdline_str") or "").lower()
        if "theseus.jar" in cmdline_str:
            theseus_in_cmdline = True
        if "argon" in cmdline_str and ("lvstrng" in cmdline_str or "dev.lvstrng" in cmdline_str):
            argon_active = True

    # Argon first (before theseus, since theseus.jar in cmdline could be from Argon too)
    if argon_active:
        return {
            "level": "CRITICAL",
            "score": 100,
            "reasons": ["Argon Client detected"],
            "confidence": "High",
        }
    if argon_selfdestructed:
        return {
            "level": "CRITICAL",
            "score": 100,
            "reasons": ["Argon Client detected (Self-Destructed)"],
            "confidence": "High",
        }
    if doomsday_active:
        return {
            "level": "CRITICAL",
            "score": 100,
            "reasons": ["DoomsdayClient detected"],
            "confidence": "High",
        }
    if theseus_in_cmdline:
        return {
            "level": "CRITICAL",
            "score": 100,
            "reasons": ["DoomsdayClient detected (Self-Destructed)"],
            "confidence": "High",
        }

    injection_categories = [
        "INJECTION_API_EXEC",
        "INJECTION_API_MEMORY",
    ]

    injection_count = 0
    for cat in injection_categories:
        hits = scan_result.found_patterns.get(cat, [])
        if hits:
            unique_apis = set(h["pattern"] for h in hits)
            injection_count += len(unique_apis)
    if injection_count >= 4:
        score += 15
        reasons.append(f"Injection APIs detected: {injection_count} unique (high volume)")
    elif injection_count >= 2:
        score += 5

    injector_hits = scan_result.found_patterns.get("CHEAT_INJECTOR", [])
    if injector_hits:
        uniq_inj = sorted(set(h["pattern"] for h in injector_hits))
        score += 30
        reasons.append(f"Bytecode injection / Java-Agent signatures: {', '.join(uniq_inj[:8])}")

    config_hits = scan_result.found_patterns.get("CHEAT_CONFIG", [])
    if config_hits:
        uniq_cfg = sorted(set(h["pattern"] for h in config_hits))
        score += 20
        reasons.append(f"Cheat config/files referenced: {', '.join(uniq_cfg[:8])}")

    cheat_client_hits = scan_result.found_patterns.get("CHEAT_CLIENT", [])
    if cheat_client_hits:
        unique_clients = set((h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"]).lower() for h in cheat_client_hits)
        known_cheats = {c.lower() for c in [
            "wurst", "meteor-client", "meteorclient", "impactclient", "impact-client",
            "sigmaclient", "sigma-client", "rusherhack", "vape", "vapev4", "vape lite",
            "novoline", "salhack", "kamiblue", "kami-blue", "bleachhack",
            "doomsday", "doomsdayclient", "doomsday-client", "zeroday",
            "expensiveclient", "expensive-client",
            "inertia", "inertia-client", "vortexclient", "vortex-client",
            "thunderhack", "zeonclient", "zeon-client", "zephyrclient", "zephyr-client",
            "crosssine", "ascensionclient", "ascension-client",
            "ravenclient", "raven-client", "xatzclient", "xatz-client",
            "bladeclient", "blade-client", "dreamy",
            "slinkyclient", "slinky-client", "stalerclient", "staler-client",
            "hackedclient", "hackclient", "cheatclient", "ghost-client",
            "injection-client",
            "liquidbounce", "liquidbounceclient", "tenacity", "tenacityclient",
            "augustus", "augustusclient", "prestige", "prestigeclient",
            "fluxclient", "flux-client", "entropyclient", "entropy-client",
            "eclipseclient", "eclipse-client", "genesisclient", "genesis-client",
            "astralclient", "astral-client", "trillium", "trilliumclient",
            "pyroclient", "pyro-client",
            "phobos", "phobosclient", "pandora", "pandoraclient",
            "centred", "centredclient", "moonclient", "moon client",
            "tenebra", "tenebraclient", "constellation", "constellationclient",
            "subside", "subsideclient", "slade", "sladeclient",
            "fdpclient", "fdp-client", "3arthh4ck", "earthhack", "seppuku", "seppukuclient",
            "trouserstreak", "trouser-streak", "pandaware", "wexside",
            "nulline", "exhibition", "komorebi", "rinami", "vergil", "koid",
            "sakura", "sakuraclient", "photonclient", "wavyclient", "cinnabar",
            "futureclient", "future-client", "riseclient", "rise-client",
            "nullify", "akrien", "metaclient", "meta-client",
            "nocomhack", "nocom-hack", "testclient",
            "aquaclient", "aqua-client", "aristois",
            "catalystclient", "catalyst-client", "crystalclient", "crystal-client",
            "ghostclient", "infernoclient", "inferno-client",
            "lambdaclient", "lambda-client", "nightx",
            "nitroclient", "nitro-client", "particleclient", "particle-client",
            "phantomclient", "phantom-client", "poohclient", "pooh-client",
            "smokeclient", "smoke-client",
            "atomclient", "atom-client", "zenclient", "zen-client",
            "argon", "argonclient", "argon-client", "argon-b1",
        ]}
        real_cheats = unique_clients & known_cheats
        if real_cheats:
            score += 50
            reasons.append(f"Known cheat clients detected: {', '.join(sorted(real_cheats))}")

    all_cheat_module_hits = []
    for scan_cat in ALL_CHEAT_MODULE_SCAN_CATS:
        hits = scan_result.found_patterns.get(scan_cat, [])
        all_cheat_module_hits.extend(hits)

    if all_cheat_module_hits:
        unique_modules = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in all_cheat_module_hits)

        high_risk_modules = {
            "KillAura", "killaura", "Kill_Aura", "Kill Aura",
            "CrystalAura", "Crystal Aura", "crystalaura",
            "MaceAura", "Mace Aura", "maceaura",
            "AimBot", "aimbot", "Aimbot",
            "BowAimbot", "Bow Aimbot", "bowaimbot",
            "TriggerBot", "triggerbot",
            "AutoCrystal", "Auto Crystal", "autocrystal",
            "AnchorExploder", "Anchor Exploder",
            "XRay", "xray", "X-Ray", "x-ray",
            "NoClip", "noclip",
            "Freecam", "freecam", "FreeCam",
            "AutoClicker", "autoclicker", "Auto Clicker",
            "PacketFly", "packetfly",
            "phase-hack",
            "Reach", "ReachHack", "reach-hack",
            "AntiKnockback", "antiknockback",
            "SpeedHack", "speed-hack",
            "FlyHack", "fly-hack", "Fly",
            "NoFall", "nofall",
            "Nuker", "nuker-hack",
            "AutoAnchor", "autoanchor", "AnchorAura", "anchoraura",
            "MaceCombo", "macecombo", "MaceSpam", "macespam",
            "Backtrack", "BackTrack", "AutoCrit", "autocrit",
            "PearlAura", "pearlaura", "AutoPearl", "autopearl",
            "AntiAim", "antiaim", "Spinbot", "spinbot",
            "BlatantAura", "blatantaura", "PotAimbot", "potaimbot",
            "WitherAura", "witheraura", "BedAura", "bedaura",
            "OneTapMace", "onetapmace", "MaceInsta", "maceinsta",
            "BoatFly", "boatfly", "ElytraFly", "elytrafly",
            "AutoAnchorPlace", "autoanchorplace", "PacketMine", "packetmine",
        }
        high_risk_found = unique_modules & high_risk_modules
        if high_risk_found:
            score += 40
            reasons.append(f"High-risk cheat modules: {', '.join(sorted(high_risk_found))}")

        evasion_modules = {
            "SelfDestruct", "Self Destruct", "selfdestruct",
            "USNJournalCleaner", "USN Journal Cleaner", "usnjournalcleaner",
            "DeleteUSNJournal", "Delete USN Journal", "deleteusnjournal",
            "GenericSelfdestruct", "Generic Selfdestruct", "genericselfdestruct",
            "StringCleaner", "String Cleaner", "stringcleaner",
            "AntiSSTool", "Anti SS Tool", "antisstool",
            "FakeLag", "Fake Lag", "fakelag",
            "PingSpoof", "Ping Spoof", "pingspoof",
            "PackSpoof", "Pack Spoof", "packspoof",
            "StrayBypass", "Stray Bypass", "straybypass",
            "DonutSMPBypass", "Donut SMP Bypass", "donutsmpbypass",
            "AntiScreenShare", "antiscreenshare", "AntiSS",
            "ScreenShareBypass", "screensharebypass",
            "ProcessHider", "processhider", "HideProcess",
            "ClearLogs", "clearlogs", "WipeTraces", "wipetraces",
            "PrefetchCleaner", "prefetchcleaner", "AntiForensics", "antiforensics",
            "AntiStaff", "antistaff", "StaffDetector", "staffdetector",
            "GrimBypass", "grimbypass", "VulcanBypass", "vulcanbypass",
            "MatrixBypass", "matrixbypass", "NCPBypass", "ncpbypass",
            "VerusBypass", "verusbypass", "PolarBypass", "polarbypass",
            "IntaveBypass", "intavebypass", "AntiCheatBypass", "anticheatbypass",
            "SpoofMods", "spoofmods", "BrandSpoofer", "brandspoofer",
        }
        evasion_found = unique_modules & evasion_modules
        if evasion_found:
            score += 35
            reasons.append(f"EVASION/SELF-DESTRUCT modules: {', '.join(sorted(evasion_found))}")

        if len(unique_modules) > 5:
            score += 15

    # Obfuscation detection scoring
    obf_hits = scan_result.found_patterns.get("OBFUSCATION", [])
    if obf_hits:
        unique_obf = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in obf_hits)
        high_risk_obf = {
            "EncryptedString", "encryptedstring",
            "StringEncrypter", "stringencrypter",
            "StringObfuscator", "stringobfuscator",
            "BytecodeEncryptor", "bytecodeencryptor",
            "BytecodeObfuscator", "bytecodeobfuscator",
            "CodeEncryption", "codeencryption",
            "CodeVirtualization", "codevirtualization",
            "NativeObfuscator", "nativeobfuscator",
            "JNIObfuscator", "jniobfuscator",
            "AntiDecompiler", "antidecompiler",
            "AntiDebug", "antidebug",
            "AntiDump", "antidump",
            "AntiTamper", "antitamper",
            "RuntimeDecryption", "runtimedecryption",
            "ReflectionHack", "reflectionhack",
            "ClassLoaderHack", "classloaderhack",
            "JVMHack", "jvmhack",
            "sun.misc.Unsafe", "sun/misc/Unsafe",
            "UnsafeAllocateInstance", "unsafeallocateinstance",
        }
        high_risk_obf_found = unique_obf & high_risk_obf
        if high_risk_obf_found:
            score += 25
            reasons.append(f"Obfuscation / anti-analysis detected: {', '.join(sorted(high_risk_obf_found))}")
        elif len(unique_obf) >= 3:
            score += 10
            reasons.append(f"Obfuscation indicators found: {len(unique_obf)} unique")

    # Mixin / Bytecode manipulation scoring
    mixin_hits = scan_result.found_patterns.get("MIXIN_BYTECODE", [])
    if mixin_hits:
        unique_mixin = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in mixin_hits)
        high_risk_mixin = {
            "org.spongepowered.asm.mixin", "org/spongepowered/asm/mixin",
            "MixinMinecraftClient", "MixinEntityPlayer",
            "MixinNetworkManager", "MixinPlayerControllerMP",
            "MixinEntityRenderer", "MixinC06PacketPlayer",
            "IClassTransformer", "LaunchClassLoader",
            "IFMLLoadingPlugin", "ClassPatchManager",
        }
        high_risk_mixin_found = unique_mixin & high_risk_mixin
        if high_risk_mixin_found:
            score += 20
            reasons.append(f"Mixin / bytecode manipulation detected: {', '.join(sorted(high_risk_mixin_found))}")
        elif len(unique_mixin) >= 3:
            score += 8
            reasons.append(f"Mixin framework indicators: {len(unique_mixin)} unique")

    # Event Bus scoring — cheat clients always register custom event handlers
    event_hits = scan_result.found_patterns.get("EVENT_BUS", [])
    if event_hits:
        unique_events = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in event_hits)
        cheat_event_patterns = {
            "PreMotionEvent", "PostMotionEvent", "MotionEvent",
            "PacketEvent", "AttackEvent", "RenderEvent",
            "onMotion", "onPacket", "onAttack",
            "onPacketSend", "onPacketReceive",
            "@Subscribe", "@EventHandler",
        }
        cheat_events_found = unique_events & cheat_event_patterns
        if cheat_events_found:
            score += 15
            reasons.append(f"Cheat event bus / handler patterns: {', '.join(sorted(cheat_events_found))}")
        elif len(unique_events) >= 5:
            score += 5
            reasons.append(f"Event handler patterns: {len(unique_events)} unique")

    # Rotation / Aim scoring — advanced clients use rotation managers
    rotation_hits = scan_result.found_patterns.get("ROTATION_AIM", [])
    if rotation_hits:
        unique_rot = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in rotation_hits)
        high_risk_rot = {
            "RotationManager", "RotatorManager",
            "SilentRotation", "RotationHack",
            "AimProcessor", "RotationProcessor",
            "SilentAim", "SilentLook",
            "YawLock", "PitchLock",
        }
        high_risk_rot_found = unique_rot & high_risk_rot
        if high_risk_rot_found:
            score += 20
            reasons.append(f"Rotation / aim manipulation detected: {', '.join(sorted(high_risk_rot_found))}")
        elif len(unique_rot) >= 3:
            score += 8
            reasons.append(f"Rotation / aim indicators: {len(unique_rot)} unique")

    # Packet manipulation scoring
    packet_hits = scan_result.found_patterns.get("PACKET_MANIPULATION", [])
    if packet_hits:
        unique_pkt = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in packet_hits)
        high_risk_pkt = {
            "PacketInterceptor", "PacketCancel", "PacketModify",
            "PacketSpoof", "CancelPacket", "ModifyPacket",
            "InjectPacket", "ChannelInterceptor",
            "NettyInterceptor",
        }
        high_risk_pkt_found = unique_pkt & high_risk_pkt
        if high_risk_pkt_found:
            score += 20
            reasons.append(f"Packet manipulation detected: {', '.join(sorted(high_risk_pkt_found))}")
        elif len(unique_pkt) >= 5:
            score += 8
            reasons.append(f"Packet handling indicators: {len(unique_pkt)} unique")

    # Config / Settings scoring
    config_hits = scan_result.found_patterns.get("CONFIG_SETTINGS", [])
    if config_hits:
        unique_cfg = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in config_hits)
        high_risk_cfg = {
            "modules.json", "clickgui.json", "hud.json",
            "ConfigManager", "configmanager",
            "SettingsManager", "settingsmanager",
            "ProfileManager", "profilemanager",
            "KeyBindManager", "keybindmanager",
            "bindManager", "bindmanager",
        }
        high_risk_cfg_found = unique_cfg & high_risk_cfg
        if high_risk_cfg_found:
            score += 15
            reasons.append(f"Cheat config / settings system: {', '.join(sorted(high_risk_cfg_found))}")
        elif len(unique_cfg) >= 3:
            score += 5
            reasons.append(f"Config indicators: {len(unique_cfg)} unique")

    # Command System scoring
    cmd_hits = scan_result.found_patterns.get("COMMAND_SYSTEM", [])
    if cmd_hits:
        unique_cmd = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in cmd_hits)
        high_risk_cmd = {
            "CommandManager", "commandmanager",
            "CommandProcessor", "commandprocessor",
            "CommandDispatcher", "commanddispatcher",
            ".toggle", ".bind", ".selfdestruct", ".panic",
            "PanicCommand", "paniccommand",
            "setPrefix", "setprefix",
            "executeCommand", "executecommand",
        }
        high_risk_cmd_found = unique_cmd & high_risk_cmd
        if high_risk_cmd_found:
            score += 15
            reasons.append(f"Cheat command system: {', '.join(sorted(high_risk_cmd_found))}")
        elif len(unique_cmd) >= 3:
            score += 5
            reasons.append(f"Command indicators: {len(unique_cmd)} unique")

    # HUD / ClickGUI scoring
    hud_hits = scan_result.found_patterns.get("HUD_CLICKGUI", [])
    if hud_hits:
        unique_hud = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in hud_hits)
        high_risk_hud = {
            "ClickGUI", "ClickGui", "clickgui",
            "HUDManager", "HudManager", "hudmanager",
            "DraggableComponent", "draggablecomponent",
            "ModuleButton", "modulebutton",
            "Watermark", "watermark",
            "ArrayListRender", "arraylistrender",
            "TabGui", "TabGUI", "tabgui",
            "NotificationManager", "notificationmanager",
        }
        high_risk_hud_found = unique_hud & high_risk_hud
        if high_risk_hud_found:
            score += 15
            reasons.append(f"Cheat HUD / ClickGUI system: {', '.join(sorted(high_risk_hud_found))}")
        elif len(unique_hud) >= 3:
            score += 5
            reasons.append(f"HUD indicators: {len(unique_hud)} unique")

    # Friend System scoring
    friend_hits = scan_result.found_patterns.get("FRIEND_SYSTEM", [])
    if friend_hits:
        unique_friend = set(h["pattern"].decode("ascii", "replace") if isinstance(h["pattern"], bytes) else h["pattern"] for h in friend_hits)
        high_risk_friend = {
            "FriendManager", "friendmanager",
            "FriendList", "friendlist",
            "isFriend", "isfriend",
            "addFriend", "addfriend",
            "EnemyManager", "enemymanager",
            "TargetManager", "targetmanager",
            "friends.json",
        }
        high_risk_friend_found = unique_friend & high_risk_friend
        if high_risk_friend_found:
            score += 10
            reasons.append(f"Cheat friend / target system: {', '.join(sorted(high_risk_friend_found))}")
        elif len(unique_friend) >= 3:
            score += 3
            reasons.append(f"Friend system indicators: {len(unique_friend)} unique")

    # Category Cross-Referencing — multiple advanced categories together = almost certainly a cheat client
    advanced_cats_present = sum(1 for cat in ["MIXIN_BYTECODE", "EVENT_BUS", "ROTATION_AIM",
                                               "PACKET_MANIPULATION", "CONFIG_SETTINGS",
                                               "COMMAND_SYSTEM", "HUD_CLICKGUI", "FRIEND_SYSTEM"]
                                if scan_result.found_patterns.get(cat, []))
    if advanced_cats_present >= 3:
        score += 15
        reasons.append(f"Category cross-reference: {advanced_cats_present} advanced categories detected simultaneously")
    elif advanced_cats_present >= 2:
        score += 5

    # Legitimate Mod Whitelist — reduce score if legit client patterns are present
    legit_patterns = set()
    for h in scan_result.found_patterns.get("MINECRAFT_IDENTIFIER", []):
        p = h["pattern"].decode("ascii", "replace").lower() if isinstance(h["pattern"], bytes) else h["pattern"].lower()
        if any(lg in p for lg in ["lunar client", "badlion client", "feather", "essential",
                                   "optifine", "optifabric", "labymod", "pvplounge",
                                   "salwyrr", "mcpclient", "cleanroom"]):
            legit_patterns.add(p)
    if legit_patterns and score >= 20:
        score -= 10
        reasons.append(f"Legitimate client detected (score reduced): {', '.join(sorted(legit_patterns)[:3])}")

    # Heuristic Mode — unknown cheat client suspected when multiple categories match but no known client
    known_client_matched = bool(scan_result.found_patterns.get("CHEAT_CLIENT", []))
    if not known_client_matched and not argon_active and not argon_selfdestructed and not doomsday_active:
        if advanced_cats_present >= 3 and score >= 30:
            score += 10
            reasons.append("Heuristic: unknown cheat client suspected (multiple framework categories matched, no known client)")

    # Obfuscation boost — if obfuscation is present AND other cheat patterns found, boost score
    obf_present = bool(scan_result.found_patterns.get("OBFUSCATION", []))
    if obf_present and score >= 20:
        score += 10
        reasons.append("Obfuscation boost: cheat patterns combined with obfuscation increase suspicion")

    # EncryptedString override — if EncryptedString found but no known client matched, warn
    enc_str_hits = scan_result.found_patterns.get("OBFUSCATION", [])
    has_encrypted_string = any(
        "encryptedstring" in (h.get("pattern", b"").decode("ascii", "replace").lower() if isinstance(h.get("pattern"), bytes) else h.get("pattern", "").lower())
        for h in enc_str_hits
    )
    if has_encrypted_string and not argon_active and not argon_selfdestructed and not doomsday_active:
        score += 15
        reasons.append("EncryptedString detected — possible obfuscated cheat client (e.g. Argon variant)")

    serious_strings = [s for s in scan_result.found_strings
                       if any(kw in s["string"].lower() for kw in [
                           "killaura", "aimbot", "vape", "wurst", "selfdestruct", "self-destruct",
                           "stringcleaner", "string cleaner", "antisstool", "anti ss",
                           "fakelag", "fake lag",
                           "pingspoof", "ping spoof", "doomsday",
                       ])]
    if serious_strings:
        score += 10
        reasons.append(f"Cheat-relevant strings: {len(serious_strings)}")

    # Confidence level calculation
    total_unique_patterns = 0
    for cat_hits in scan_result.found_patterns.values():
        total_unique_patterns += len(set(h["pattern"] for h in cat_hits))
    if total_unique_patterns >= 15:
        confidence = "High"
    elif total_unique_patterns >= 8:
        confidence = "Medium"
    elif total_unique_patterns >= 3:
        confidence = "Low"
    else:
        confidence = "Very Low"

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    elif score >= 10:
        level = "LOW"
    else:
        level = "CLEAN"

    return {
        "level": level,
        "score": min(score, 100),
        "reasons": reasons,
        "confidence": confidence,
    }


def print_separator(title, char="=", width=70, color=""):
    sep = char * width
    c = color or CYAN
    print(f"\n{c}{sep}{RESET}")
    print(f"{c}  {title}{RESET}")
    print(f"{c}{sep}{RESET}")


def generate_report(proc_info, scan_result, threat):
    lines = []

    def add(line=""):
        lines.append(line)
        print(line)

    print_separator(f"ANALYSIS: PID {proc_info['pid']} - {proc_info['name']}", color=MAGENTA)

    add(f"  {BOLD}Process:{RESET}       {proc_info['name']} (PID={proc_info['pid']})")
    add(f"  {BOLD}Type:{RESET}          {proc_info['mc_type']}")
    if proc_info.get("mc_version"):
        add(f"  {BOLD}MC Version:{RESET}    {proc_info['mc_version']}")
    add(f"  {BOLD}EXE:{RESET}           {proc_info['exe']}")
    add(f"  {BOLD}Command-Line:{RESET}  {proc_info['cmdline_str'][:200]}")
    if proc_info.get("create_time"):
        add(f"  {BOLD}Started:{RESET}       {proc_info['create_time']}")
    add()

    print_separator("THREAT ASSESSMENT", "-", color=YELLOW)
    color = THREAT_COLORS.get(threat["level"], "")
    add(f"  {BOLD}Threat Level:{RESET}  {color}{BOLD}{threat['level']} (Score: {threat['score']}){RESET}")
    if threat.get("confidence"):
        add(f"  {BOLD}Confidence:{RESET}     {threat['confidence']}")
    add()
    if threat["reasons"]:
        add(f"  {BOLD}Reasons:{RESET}")
        for r in threat["reasons"]:
            if "EVASION" in r or "SELF-DESTRUCT" in r:
                add(f"    {RED}- {r}{RESET}")
            elif "High-risk" in r or "Known cheat" in r:
                add(f"    {YELLOW}- {r}{RESET}")
            else:
                add(f"    {DIM}- {r}{RESET}")
    else:
        add(f"  {GREEN}No suspicious activity detected.{RESET}")
    add()

    print_separator("MEMORY SCAN RESULTS", "-", color=BLUE)
    add(f"  {BOLD}Regions scanned:{RESET}   {scan_result.regions_scanned}")
    add(f"  {BOLD}Bytes scanned:{RESET}     {scan_result.total_bytes_scanned:,}")
    add(f"  {BOLD}Errors:{RESET}            {len(scan_result.errors)}")
    for err in scan_result.errors:
        add(f"    {RED}! {err}{RESET}")
    add()

    NOISE_CATEGORIES = {
        "INJECTION_API_PROCESS", "INJECTION_API_WINDOW",
        "INJECTION_API_MEMORY", "INJECTION_API_EXEC",
        "INJECTION_API_MISC", "MINECRAFT_IDENTIFIER", "MOD_LOADER",
    }
    cheat_module_cats = set(ALL_CHEAT_MODULE_SCAN_CATS)

    for category, hits in sorted(scan_result.found_patterns.items()):
        if category in cheat_module_cats or category in NOISE_CATEGORIES:
            continue
        if not hits:
            continue
        unique_patterns = sorted(set(h["pattern"] for h in hits))
        print_separator(f"  [{category}] - {len(hits)} hits, {len(unique_patterns)} unique", "-", color=CYAN)
        for p in unique_patterns:
            count = sum(1 for h in hits if h["pattern"] == p)
            add(f"    {YELLOW}{p}{RESET} ({count}x)")
        add()
        add(f"    {DIM}Addresses (first 5):{RESET}")
        for h in hits[:5]:
            add(f"      {h['address']}  '{h['pattern']}'")
            if h["context"]:
                add(f"        {DIM}Context: {h['context'][:120]}{RESET}")
        if len(hits) > 5:
            add(f"      {DIM}... and {len(hits) - 5} more{RESET}")
        add()

    total_cheat_modules = 0
    total_cheat_hits = 0
    for scan_cat in ALL_CHEAT_MODULE_SCAN_CATS:
        hits = scan_result.found_patterns.get(scan_cat, [])
        total_cheat_hits += len(hits)
        total_cheat_modules += len(set(h["pattern"] for h in hits))

    if total_cheat_hits > 0:
        print_separator(f"DETECTED CHEAT MODULES ({total_cheat_modules} unique, {total_cheat_hits} hits)", "=", color=RED)
        add()

        for scan_cat, display_name in CHEAT_MODULE_CATEGORY_MAP.items():
            hits = scan_result.found_patterns.get(scan_cat, [])
            if not hits:
                continue
            unique_patterns = sorted(set(h["pattern"] for h in hits))
            add(f"  {BOLD}{MAGENTA}** {display_name} **{RESET} ({len(unique_patterns)} modules)")
            for p in unique_patterns:
                count = sum(1 for h in hits if h["pattern"] == p)
                add(f"    {YELLOW}- {p}{RESET} ({count}x)")
            add()
            add(f"    {DIM}Addresses (first 3):{RESET}")
            for h in hits[:3]:
                add(f"      {h['address']}  '{h['pattern']}'")
                if h["context"]:
                    add(f"        {DIM}Context: {h['context'][:120]}{RESET}")
            if len(hits) > 3:
                add(f"      {DIM}... and {len(hits) - 3} more{RESET}")
            add()
    else:
        print_separator("DETECTED CHEAT MODULES - none found", "-", color=GREEN)
        add()

    if scan_result.found_strings:
        print_separator(f"CHEAT-RELEVANT STRINGS ({len(scan_result.found_strings)} found)", "-", color=YELLOW)
        for s in scan_result.found_strings[:50]:
            add(f"  [{s['encoding']}] '{s['string'][:100]}' @ {s['address']}")
        if len(scan_result.found_strings) > 50:
            add(f"  {DIM}... and {len(scan_result.found_strings) - 50} more{RESET}")
        add()

    return "\n".join(lines)


def print_banner(is_admin):
    print()
    print(f"  {BG_MAG}{BOLD}{'='*70}{RESET}")
    print(f"  {BG_MAG}{BOLD}    YUMIKO MEMORY ANALYZER                                    {RESET}")
    print(f"  {BG_MAG}{BOLD}{'='*70}{RESET}")
    print()
    print(f"  {CYAN}GitHub:{RESET}  {GITHUB_URL}")
    print(f"  {CYAN}Discord:{RESET} {DISCORD_TAG}")
    print(f"  {DIM}Version: {SCANNER_VERSION}{RESET}")
    print()
    print(f"  {DIM}Scans Java processes for cheats in memory.{RESET}")
    print(f"  {DIM}Read-only analysis - no data sent online.{RESET}")
    print()
    if not is_admin:
        print(f"  {BOLD}{RED}[WARNING] No admin rights! Memory scan will likely fail.{RESET}")
        print(f"  {DIM}Please run as Administrator for full scan.{RESET}")
        print()
    else:
        print(f"  {BOLD}{GREEN}[OK] Admin rights detected - full scan possible.{RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Yumiko Memory Analyzer - scans Java processes for cheats in memory"
    )
    parser.add_argument("--pid", "-p", type=int, default=None,
                        help="Scan specific PID (instead of auto-discovery)")
    parser.add_argument("--output", "-o", default=None,
                        help="Save JSON report to file")
    parser.add_argument("--continuous", "-c", action="store_true",
                        help="Continuous scan mode")
    parser.add_argument("--interval", "-i", type=float, default=5.0,
                        help="Scan interval in seconds (only with --continuous)")
    parser.add_argument("--deep", "-d", action="store_true",
                        help="Deep scan (scan all memory regions, not just writable)")
    parser.add_argument("--timeout", "-t", type=int, default=MAX_SCAN_SECONDS,
                        help=f"Max seconds per process scan (0 = unlimited, default {MAX_SCAN_SECONDS})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    enable_ansi()

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    print_banner(is_admin)

    if args.continuous:
        run_continuous(args)
    else:
        run_single_scan(args)


def run_single_scan(args):
    if args.pid:
        try:
            proc = psutil.Process(args.pid)
            proc_info = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() or "",
                "cmdline": proc.cmdline(),
                "cmdline_str": " ".join(proc.cmdline()),
                "mc_type": "manual-pid",
                "mc_version": None,
                "create_time": datetime.datetime.fromtimestamp(
                    proc.create_time()
                ).isoformat(),
            }
            processes = [proc_info]
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"  {RED}[ERROR] Process PID={args.pid} not found: {e}{RESET}")
            sys.exit(1)
    else:
        print(f"  {CYAN}Searching for Minecraft processes...{RESET}")
        processes = find_java_processes()

    if not processes:
        print()
        print(f"  {YELLOW}[INFO] No Minecraft processes found.{RESET}")
        print(f"  {DIM}Make sure Minecraft is running.{RESET}")
        print()
        input(f"  {DIM}Press Enter to exit...{RESET}")
        return

    print()
    print(f"  {GREEN}{len(processes)} Minecraft process(es) found:{RESET}")
    for p in processes:
        print(f"    {BOLD}PID={p['pid']:6d}{RESET}  {p['name']:20s}  {CYAN}Type: {p['mc_type']}{RESET}"
              + (f"  {DIM}Version: {p['mc_version']}{RESET}" if p.get("mc_version") else ""))
    print()

    all_reports = []
    all_json = []

    for proc_info in processes:
        pid = proc_info["pid"]
        print()
        print(f"  {BOLD}{BLUE}Scanning PID={pid} ({proc_info['name']}){RESET}")

        scan_result = scan_process_memory(pid, verbose=args.verbose, deep=args.deep, show_progress=True, time_budget=args.timeout)
        threat = assess_threat_level(scan_result, proc_info=proc_info)
        report_text = generate_report(proc_info, scan_result, threat)
        all_reports.append(report_text)

        proc_json = {
            "pid": pid,
            "name": proc_info["name"],
            "exe": proc_info["exe"],
            "cmdline": proc_info["cmdline"],
            "mc_type": proc_info["mc_type"],
            "mc_version": proc_info.get("mc_version"),
            "create_time": proc_info.get("create_time"),
            "threat": threat,
            "memory_scan": {
                "regions_scanned": scan_result.regions_scanned,
                "total_bytes_scanned": scan_result.total_bytes_scanned,
                "errors": scan_result.errors,
                "patterns_found": {
                    cat: hits for cat, hits in scan_result.found_patterns.items()
                },
                "cheat_strings": scan_result.found_strings,
            },
        }
        all_json.append(proc_json)

    print()
    print_separator("SUMMARY", color=MAGENTA)
    for proc_json in all_json:
        t = proc_json["threat"]
        tc = THREAT_COLORS.get(t["level"], "")
        print(f"  {BOLD}PID={proc_json['pid']:6d}{RESET}  {proc_json['name']:20s}  "
              f"{tc}Threat: {t['level']:8s}  Score: {t['score']:3d}{RESET}")
        for r in t["reasons"]:
            print(f"    {DIM}- {r}{RESET}")
    print()

    if args.output:
        output_path = os.path.abspath(args.output)
    else:
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"cheat_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

    export = {
        "scan_time": datetime.datetime.now().isoformat(),
        "scanner": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "github": GITHUB_URL,
        "discord": DISCORD_TAG,
        "processes_scanned": len(all_json),
        "results": all_json,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export, f, ensure_ascii=False, indent=2, default=str)
    print(f"  {GREEN}JSON report: {output_path}{RESET}")
    print()

    print(f"  {DIM}GitHub: {GITHUB_URL}  |  Discord: {DISCORD_TAG}{RESET}")
    print()
    input(f"  {DIM}Press Enter to exit...{RESET}")


def run_continuous(args):
    print(f"  {CYAN}Continuous mode (interval: {args.interval}s){RESET}")
    print(f"  {DIM}Ctrl+C to stop{RESET}")
    print()

    seen_pids = set()
    scan_number = 0

    try:
        while True:
            scan_number += 1
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\n{BG_BLUE}{'='*70}{RESET}")
            print(f"{BG_BLUE}  Scan #{scan_number} - {timestamp}{'':>32}{RESET}")
            print(f"{BG_BLUE}{'='*70}{RESET}")

            processes = find_java_processes()

            if not processes:
                print(f"  {YELLOW}No Minecraft processes found.{RESET}")
            else:
                for proc_info in processes:
                    pid = proc_info["pid"]
                    if pid in seen_pids:
                        scan_result = scan_process_memory(pid)
                        threat = assess_threat_level(scan_result, proc_info=proc_info)

                        level_indicator = {
                            "CRITICAL": f"{RED}!!!{RESET}",
                            "HIGH":     f"{YELLOW}!!{RESET}",
                            "MEDIUM":   f"{CYAN}!{RESET}",
                            "LOW":      f"{GREEN}.{RESET}",
                            "CLEAN":    f"{GREEN}OK{RESET}",
                        }
                        ind = level_indicator.get(threat["level"], "?")
                        tc = THREAT_COLORS.get(threat["level"], "")
                        print(f"  [{ind}] PID={pid:6d} {proc_info['name']:20s} "
                              f"{tc}Threat={threat['level']:8s} Score={threat['score']:3d}{RESET}")

                        if threat["level"] in ("CRITICAL", "HIGH"):
                            for r in threat["reasons"]:
                                print(f"       {DIM}- {r}{RESET}")
                    else:
                        seen_pids.add(pid)
                        print(f"  {GREEN}[NEW]{RESET} PID={pid:6d} {proc_info['name']:20s} "
                              f"{CYAN}Type: {proc_info['mc_type']}{RESET}")

                        scan_result = scan_process_memory(pid)
                        threat = assess_threat_level(scan_result, proc_info=proc_info)

                        tc = THREAT_COLORS.get(threat["level"], "")
                        print(f"  {tc}Threat: {threat['level']} (Score: {threat['score']}){RESET}")
                        for r in threat["reasons"]:
                            print(f"    {DIM}- {r}{RESET}")

                        if threat["level"] in ("CRITICAL", "HIGH"):
                            print()
                            print(f"  {BOLD}{RED}*** WARNING: SUSPICIOUS PROCESS DETECTED ***{RESET}")
                            print(f"  {DIM}See details above.{RESET}")

            current_pids = {p["pid"] for p in processes}
            ended = seen_pids - current_pids
            for pid in ended:
                print(f"  {DIM}[ENDED] PID={pid} process terminated{RESET}")
                seen_pids.discard(pid)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print()
        print(f"  {YELLOW}Scan stopped by user.{RESET}")
        print(f"  {DIM}GitHub: {GITHUB_URL}  |  Discord: {DISCORD_TAG}{RESET}")
        print()


if __name__ == "__main__":
    main()
