#!/data/data/com.termux/files/usr/bin/python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Xnode-sh — RED └•TEAM•┐ lab™
"""
frewb — Firmware RE Workbench
Автономный набор инструментов для реверс-инжиниринга прошивок на Android/Termux.
"""

import os
import sys
import subprocess
import json
import sqlite3
import hashlib
import shutil
import tempfile
import threading
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DB_PATH = Path.home() / "frewb" / "frewb.db"
WORK_DIR = Path.home() / "frewb" / "work"
TOOLS_DIR = Path.home() / "frewb" / "tools"

REQUIRED_TOOLS = [
    "strings", "file",
]

OPTIONAL_TOOLS = [
    "binwalk", "qemu-arm-static", "qemu-aarch64-static", "qemu-mips-static", "qemu-mips64-static",
    "qemu-i386-static", "qemu-x86_64-static",
    "flashrom", "openocd", "arm-none-eabi-objdump", "arm-none-eabi-readelf",
    "ghidra", "ida", "radare2", "firmwalker", "sasquatch", "jefferson"
]

ARCH_MAP = {
    "ARM": "arm",
    "AARCH64": "aarch64",
    "MIPS": "mips",
    "MIPS64": "mips64",
    "X86": "i386",
    "X86_64": "x86_64",
    "POWERPC": "ppc",
}

class FirmwareDB:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        self.con = sqlite3.connect(DB_PATH)
        self.con.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self.con.executescript("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                path TEXT NOT NULL,
                target_device TEXT,
                soc TEXT,
                flash_type TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS firmware_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                mime_type TEXT,
                arch TEXT,
                endian TEXT,
                entry_point TEXT,
                load_address TEXT,
                extracted_path TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                offset INTEGER,
                size INTEGER,
                description TEXT,
                data TEXT,
                tags TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(image_id) REFERENCES firmware_images(id)
            );
            CREATE TABLE IF NOT EXISTS symbols (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                name TEXT NOT NULL,
                type TEXT,
                size INTEGER,
                FOREIGN KEY(image_id) REFERENCES firmware_images(id)
            );
            CREATE TABLE IF NOT EXISTS hardware_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                interface_type TEXT NOT NULL,
                pins TEXT,
                protocol TEXT,
                baudrate INTEGER,
                voltage REAL,
                notes TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_image ON findings(image_id);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_symbols_image ON symbols(image_id);
        """)

    def create_project(self, name, target_device="", soc="", flash_type=""):
        now = datetime.now().isoformat()
        path = WORK_DIR / name
        path.mkdir(parents=True, exist_ok=True)
        cur = self.con.execute(
            "INSERT INTO projects (name, path, target_device, soc, flash_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, str(path), target_device, soc, flash_type, now, now)
        )
        self.con.commit()
        return cur.lastrowid

    def add_image(self, project_id, filepath):
        path = Path(filepath).expanduser().resolve(strict=True)
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        size = path.stat().st_size
        mime = subprocess.run(["file", "-b", "--mime-type", str(path)], capture_output=True, text=True).stdout.strip()
        now = datetime.now().isoformat()
        cur = self.con.execute(
            """INSERT INTO firmware_images (project_id, filename, sha256, size, mime_type, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (project_id, str(path), sha256, size, mime, now)
        )
        self.con.commit()
        return cur.lastrowid, sha256

    def update_image_analysis(self, image_id, arch, endian, entry_point, load_address, extracted_path):
        self.con.execute(
            """UPDATE firmware_images SET arch=?, endian=?, entry_point=?, load_address=?, extracted_path=?
               WHERE id=?""",
            (arch, endian, entry_point, load_address, extracted_path, image_id)
        )
        self.con.commit()

    def add_finding(self, image_id, ftype, offset, size, description, data="", tags=""):
        self.con.execute(
            """INSERT INTO findings (image_id, type, offset, size, description, data, tags, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (image_id, ftype, offset, size, description, data, tags, datetime.now().isoformat())
        )
        self.con.commit()

    def add_symbol(self, image_id, address, name, stype="", size=0):
        self.con.execute(
            """INSERT INTO symbols (image_id, address, name, type, size) VALUES (?, ?, ?, ?, ?)""",
            (image_id, address, name, stype, size)
        )
        self.con.commit()

    def add_hw_interface(self, project_id, itype, pins, protocol, baudrate, voltage, notes):
        self.con.execute(
            """INSERT INTO hardware_interfaces (project_id, interface_type, pins, protocol, baudrate, voltage, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (project_id, itype, pins, protocol, baudrate, voltage, notes)
        )
        self.con.commit()

    def get_project(self, name):
        return self.con.execute("SELECT * FROM projects WHERE name=?", (name,)).fetchone()

    def list_projects(self):
        return self.con.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()

    def get_images(self, project_id):
        return self.con.execute("SELECT * FROM firmware_images WHERE project_id=?", (project_id,)).fetchall()

    def get_findings(self, image_id, ftype=None):
        if ftype:
            return self.con.execute("SELECT * FROM findings WHERE image_id=? AND type=?", (image_id, ftype)).fetchall()
        return self.con.execute("SELECT * FROM findings WHERE image_id=?", (image_id,)).fetchall()

    def get_symbols(self, image_id):
        return self.con.execute("SELECT * FROM symbols WHERE image_id=? ORDER BY address", (image_id,)).fetchall()

    def get_hw_interfaces(self, project_id):
        return self.con.execute("SELECT * FROM hardware_interfaces WHERE project_id=?", (project_id,)).fetchall()


class FirmwareAnalyzer:
    def __init__(self, db):
        self.db = db

    def analyze(self, image_id, filepath, previous_extraction=""):
        path = Path(filepath)
        print(f"[+] Analyzing {path.name}...")

        if not path.is_file():
            raise FileNotFoundError(f"Firmware image not found: {path}")

        binwalk_available = shutil.which("binwalk")
        if binwalk_available:
            self._run_binwalk(image_id, path)
        else:
            print("  [binwalk] Unavailable. Skipping signatures, entropy and extraction.")

        self._run_strings(image_id, path)
        if binwalk_available:
            self._run_entropy(image_id, path)

        arch, endian, entry, load_addr = self._detect_arch(image_id, path)
        extracted = self._extract_firmware(image_id, path) if binwalk_available else previous_extraction

        self.db.update_image_analysis(image_id, arch, endian, entry, load_addr, extracted)
        print(f"[+] Analysis complete. Arch: {arch}, Endian: {endian}")

    def _run_binwalk(self, image_id, path):
        print("  [binwalk] Scanning...")
        result = subprocess.run(["binwalk", "-B", "-M", "--json", str(path)], capture_output=True, text=True, timeout=300)
        try:
            data = json.loads(result.stdout)
            for module in data:
                for res in module.get("results", []):
                    offset = res.get("offset", 0)
                    desc = res.get("description", "")
                    ftype = self._classify_binwalk(desc)
                    self.db.add_finding(image_id, ftype, offset, 0, desc, tags="binwalk")
        except Exception as e:
            print(f"  [binwalk] JSON parse error: {e}")

    def _classify_binwalk(self, desc):
        desc_lower = desc.lower()
        if any(x in desc_lower for x in ["u-boot", "uboot", "cfe", "bolt", "bootloader"]):
            return "bootloader"
        if any(x in desc_lower for x in ["linux kernel", "kernel"]):
            return "kernel"
        if any(x in desc_lower for x in ["squashfs", "jffs2", "yaffs", "cramfs", "ext2", "ext3", "ext4", "ubifs"]):
            return "filesystem"
        if any(x in desc_lower for x in ["certificate", "rsa", "dsa", "ecdsa", "public key", "private key"]):
            return "crypto"
        if any(x in desc_lower for x in ["lzma", "gzip", "zlib", "xz", "lz4"]):
            return "compression"
        if "device tree" in desc_lower:
            return "dtb"
        return "other"

    def _run_strings(self, image_id, path):
        print("  [strings] Extracting...")
        result = subprocess.run(["strings", "-n", "6", "-t", "x", str(path)], capture_output=True, text=True, timeout=60)
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                try:
                    offset = int(parts[0], 16)
                    string = parts[1]
                    if any(kw in string.lower() for kw in ["password", "admin", "root", "secret", "key", "token", "api", "url", "http", "ftp", "telnet", "ssh", "uart", "gpio", "i2c", "spi", "jtag", "debug", "test", "factory", "bootcmd", "bootargs", "console", "mtd", "partition"]):
                        self.db.add_finding(image_id, "interesting_string", offset, len(string), string, tags="strings,high_value")
                    elif len(string) > 40:
                        self.db.add_finding(image_id, "long_string", offset, len(string), string[:200], tags="strings")
                except ValueError:
                    pass

    def _run_entropy(self, image_id, path):
        print("  [entropy] Calculating...")
        try:
            result = subprocess.run(["binwalk", "-E", "-J", str(path)], capture_output=True, text=True, timeout=120)
            data = json.loads(result.stdout)
            for module in data:
                for res in module.get("results", []):
                    offset = res.get("offset", 0)
                    entropy = res.get("entropy", 0)
                    if entropy > 7.5:
                        self.db.add_finding(image_id, "high_entropy", offset, 0, f"Entropy: {entropy:.2f} (encrypted/compressed)", tags="entropy")
        except Exception:
            pass

    def _detect_arch(self, image_id, path):
        result = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True)
        out = result.stdout
        arch = endian = entry = load_addr = "unknown"

        if "ARM" in out and "64" in out:
            arch = "AARCH64"
        elif "ARM" in out:
            arch = "ARM"
        elif "MIPS" in out and "64" in out:
            arch = "MIPS64"
        elif "MIPS" in out:
            arch = "MIPS"
        elif "x86-64" in out:
            arch = "X86_64"
        elif "x86" in out or "i386" in out:
            arch = "X86"

        if "little endian" in out.lower():
            endian = "little"
        elif "big endian" in out.lower():
            endian = "big"

        # Try readelf for entry point
        try:
            r = subprocess.run(["arm-none-eabi-readelf", "-h", str(path)], capture_output=True, text=True, timeout=30)
            for line in r.stdout.split('\n'):
                if "Entry point" in line:
                    entry = line.split("0x")[-1].strip()
                if "Load address" in line or "Start address" in line:
                    load_addr = line.split("0x")[-1].strip()
        except Exception:
            pass

        return arch, endian, entry, load_addr

    def _extract_firmware(self, image_id, path):
        extract_dir = WORK_DIR / f"extracted_{image_id}"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        print(f"  [extract] Extracting to {extract_dir}...")
        result = subprocess.run(["binwalk", "-e", "-C", str(extract_dir), str(path)], capture_output=True, text=True, timeout=300)
        return str(extract_dir) if extract_dir.exists() else ""


class QEMUEmulator:
    def __init__(self, db):
        self.db = db

    def run_binary(self, image_id, binary_path, args="", env_vars=None):
        image = self.db.con.execute("SELECT * FROM firmware_images WHERE id=?", (image_id,)).fetchone()
        if not image:
            return "Image not found"

        arch = image["arch"]
        qemu_bin = self._get_qemu(arch)
        if not qemu_bin:
            return f"No QEMU for arch {arch}"

        # Find libc/ld.so in extracted fs
        extracted = image["extracted_path"]
        rootfs = self._find_rootfs(extracted) if extracted else None

        cmd = [qemu_bin]
        if rootfs:
            cmd += ["-L", rootfs]
        cmd += [binary_path] + args.split()

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        print(f"[qemu] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        return result.stdout + result.stderr

    def _get_qemu(self, arch):
        mapping = {
            "ARM": "qemu-arm-static",
            "AARCH64": "qemu-aarch64-static",
            "MIPS": "qemu-mips-static",
            "MIPS64": "qemu-mips64-static",
            "X86": "qemu-i386-static",
            "X86_64": "qemu-x86_64-static",
        }
        bin_name = mapping.get(arch)
        if bin_name and shutil.which(bin_name):
            return bin_name
        return None

    def _find_rootfs(self, extracted_dir):
        for root, dirs, files in os.walk(extracted_dir):
            if "lib" in dirs and "etc" in dirs:
                return root
        return None


class HardwareInterface:
    def __init__(self, db):
        self.db = db

    def scan_uart(self, project_id, device="/dev/ttyUSB0", baudrates=[115200, 9600, 57600, 230400, 38400, 19200]):
        print(f"[uart] Scanning {device} at multiple baudrates...")
        for br in baudrates:
            try:
                import serial
                ser = serial.Serial(device, br, timeout=2)
                time.sleep(0.5)
                ser.write(b"\n")
                time.sleep(0.5)
                out = ser.read_all().decode(errors="ignore")
                ser.close()
                if out.strip():
                    self.db.add_hw_interface(project_id, "UART", device, "UART", br, 3.3, f"Response: {out[:200]}")
                    print(f"  [+] {br} baud: {out[:100]}")
            except Exception as e:
                print(f"  [-] {br} baud: {e}")

    def probe_gpio(self, project_id, pin_map):
        """pin_map: {pin_num: 'function'} e.g. {14: 'TX', 15: 'RX'}"""
        for pin, func in pin_map.items():
            self.db.add_hw_interface(project_id, "GPIO", str(pin), func, 0, 3.3, f"Probed as {func}")
        print(f"[gpio] Recorded {len(pin_map)} pins")

    def spi_dump(self, project_id, chip="MX25L3205", output=None):
        if not output:
            output = WORK_DIR / f"spi_dump_{project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        cmd = ["flashrom", "-p", "ch341a_spi", "-r", str(output), "-c", chip]
        print(f"[spi] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            self.db.add_hw_interface(project_id, "SPI", "CH341A", "SPI Flash", 0, 3.3, f"Dumped to {output}")
            print(f"[+] SPI dump saved to {output}")
        else:
            print(f"[-] SPI dump failed: {result.stderr}")
        return result.returncode == 0


class ReportGenerator:
    def __init__(self, db):
        self.db = db

    def generate(self, project_id, output_path=None):
        project = self.db.con.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not project:
            return "Project not found"

        if not output_path:
            output_path = WORK_DIR / f"report_{project['name']}_{datetime.now().strftime('%Y%m%d')}.md"

        images = self.db.get_images(project_id)
        hw = self.db.get_hw_interfaces(project_id)

        with open(output_path, "w") as f:
            f.write(f"# Firmware RE Report: {project['name']}\n\n")
            f.write(f"**Device:** {project['target_device']}  \n")
            f.write(f"**SoC:** {project['soc']}  \n")
            f.write(f"**Flash:** {project['flash_type']}  \n")
            f.write(f"**Generated:** {datetime.now().isoformat()}  \n\n")

            f.write("## Hardware Interfaces\n\n")
            for h in hw:
                f.write(f"- **{h['interface_type']}** ({h['protocol']}) - Pins: {h['pins']}, Baud: {h['baudrate']}, V: {h['voltage']}  \n")
                f.write(f"  - Notes: {h['notes']}  \n\n")

            for img in images:
                f.write(f"## Image: {Path(img['filename']).name}\n\n")
                f.write(f"- SHA256: `{img['sha256']}`  \n")
                f.write(f"- Size: {img['size']} bytes  \n")
                f.write(f"- MIME: {img['mime_type']}  \n")
                f.write(f"- Arch: {img['arch']} ({img['endian']})  \n")
                f.write(f"- Entry: {img['entry_point']}  \n")
                f.write(f"- Load: {img['load_address']}  \n\n")

                findings = self.db.get_findings(img['id'])
                by_type = defaultdict(list)
                for fin in findings:
                    by_type[fin['type']].append(fin)

                for ftype, items in by_type.items():
                    f.write(f"### {ftype.replace('_', ' ').title()} ({len(items)})\n\n")
                    for item in items[:20]:
                        f.write(f"- `0x{item['offset']:X}`: {item['description'][:200]}  \n")
                    if len(items) > 20:
                        f.write(f"- ... and {len(items)-20} more  \n")
                    f.write("\n")

                symbols = self.db.get_symbols(img['id'])
                if symbols:
                    f.write(f"### Symbols ({len(symbols)})\n\n")
                    for sym in symbols[:50]:
                        f.write(f"- `0x{sym['address']}`: {sym['name']} ({sym['type']})  \n")
                    f.write("\n")

        print(f"[+] Report saved to {output_path}")
        return str(output_path)


def check_tools():
    missing = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    return missing


def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    missing = check_tools()
    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        raise SystemExit(1)

    db = FirmwareDB()
    analyzer = FirmwareAnalyzer(db)
    emulator = QEMUEmulator(db)
    hw = HardwareInterface(db)
    reporter = ReportGenerator(db)

    cmd = sys.argv[1]

    if cmd == "init":
        name = sys.argv[2] if len(sys.argv) > 2 else input("Project name: ")
        device = sys.argv[3] if len(sys.argv) > 3 else ""
        soc = sys.argv[4] if len(sys.argv) > 4 else ""
        flash = sys.argv[5] if len(sys.argv) > 5 else ""
        pid = db.create_project(name, device, soc, flash)
        print(f"[+] Project '{name}' created (ID: {pid})")

    elif cmd == "add":
        if len(sys.argv) < 4:
            print("Usage: frewb add <project> <firmware_file>")
            return
        project = db.get_project(sys.argv[2])
        if not project:
            print("Project not found")
            return
        image_id, sha256 = db.add_image(project["id"], sys.argv[3])
        print(f"[+] Added image (ID: {image_id}, SHA256: {sha256[:16]}...)")

    elif cmd == "analyze":
        if len(sys.argv) < 3:
            print("Usage: frewb analyze <image_id>")
            return
        img = db.con.execute("SELECT * FROM firmware_images WHERE id=?", (sys.argv[2],)).fetchone()
        if not img:
            print("Image not found")
            return
        try:
            analyzer.analyze(img["id"], WORK_DIR / img["filename"], img["extracted_path"])
        except FileNotFoundError as exc:
            raise SystemExit(str(exc)) from exc

    elif cmd == "emulate":
        if len(sys.argv) < 4:
            print("Usage: frewb emulate <image_id> <binary_path> [args]")
            return
        output = emulator.run_binary(sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
        print(output)

    elif cmd == "uart":
        if len(sys.argv) < 3:
            print("Usage: frewb uart <project_id> [device]")
            return
        device = sys.argv[3] if len(sys.argv) > 3 else "/dev/ttyUSB0"
        hw.scan_uart(sys.argv[2], device)

    elif cmd == "gpio":
        if len(sys.argv) < 4:
            print("Usage: frewb gpio <project_id> <pin:function,pin:function...>")
            return
        pin_map = {}
        for pair in sys.argv[3].split(","):
            pin, func = pair.split(":")
            pin_map[int(pin)] = func
        hw.probe_gpio(sys.argv[2], pin_map)

    elif cmd == "spi":
        if len(sys.argv) < 3:
            print("Usage: frewb spi <project_id> [chip]")
            return
        chip = sys.argv[3] if len(sys.argv) > 3 else "MX25L3205"
        hw.spi_dump(sys.argv[2], chip)

    elif cmd == "report":
        if len(sys.argv) < 3:
            print("Usage: frewb report <project_id> [output.md]")
            return
        output = sys.argv[3] if len(sys.argv) > 3 else None
        reporter.generate(sys.argv[2], output)

    elif cmd == "list":
        projects = db.list_projects()
        for p in projects:
            print(f"  {p['id']}: {p['name']} ({p['target_device']}) - {p['updated_at'][:19]}")

    else:
        print_usage()


def print_usage():
    print("""
frewb — Firmware RE Workbench

Usage:
  frewb init <name> [device] [soc] [flash_type]     Create project
  frewb add <project> <firmware.bin>                Add firmware image
  frewb analyze <image_id>                          Full static analysis
  frewb emulate <image_id> <binary> [args]          Run via QEMU user-mode
  frewb uart <project_id> [/dev/ttyUSB0]            Scan UART baudrates
  frewb gpio <project_id> <pin:func,pin:func...>    Record GPIO mapping
  frewb spi <project_id> [MX25L3205]                Dump SPI via CH341A
  frewb report <project_id> [output.md]             Generate Markdown report
  frewb list                                        List projects

Examples:
  frewb init vm1920 "Volia VM1920" "BCM75831" "SPI MX25L3205"
  frewb add vm1920 spi_dump.bin
  frewb analyze 1
  frewb uart 1 /dev/ttyUSB0
  frewb gpio 1 "14:TX,15:RX,16:GND"
  frewb spi 1 MX25L3205
  frewb report 1
""")


if __name__ == "__main__":
    main()
