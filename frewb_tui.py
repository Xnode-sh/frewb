#!/data/data/com.termux/files/usr/bin/python3
"""
frewb-tui — Terminal UI for Firmware RE Workbench
"""

import curses
import sqlite3
import subprocess
import os
import sys
from pathlib import Path

DB_PATH = Path.home() / "frewb" / "frewb.db"
WORK_DIR = Path.home() / "frewb" / "work"

class FrewbTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.con = sqlite3.connect(DB_PATH)
        self.con.row_factory = sqlite3.Row
        self.projects = []
        self.current_project = None
        self.current_image = None
        self.mode = "projects"  # projects, images, findings, symbols, hw, analyze, report
        self.selected = 0
        self.offset = 0
        self.input_buffer = ""
        self.input_mode = False
        self.input_prompt = ""
        self.input_callback = None

        curses.curs_set(0)
        curses.use_default_colors()
        self.stdscr.keypad(True)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, -1)    # Header
        curses.init_pair(2, curses.COLOR_GREEN, -1)   # Success
        curses.init_pair(3, curses.COLOR_YELLOW, -1)  # Warning
        curses.init_pair(4, curses.COLOR_RED, -1)     # Error
        curses.init_pair(5, curses.COLOR_MAGENTA, -1) # Highlight

    def load_projects(self):
        self.projects = self.con.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()

    def load_images(self):
        if self.current_project:
            self.images = self.con.execute("SELECT * FROM firmware_images WHERE project_id=?", (self.current_project["id"],)).fetchall()
        else:
            self.images = []

    def load_findings(self):
        if self.current_image:
            self.findings = self.con.execute("SELECT * FROM findings WHERE image_id=? ORDER BY offset", (self.current_image["id"],)).fetchall()
        else:
            self.findings = []

    def load_symbols(self):
        if self.current_image:
            self.symbols = self.con.execute("SELECT * FROM symbols WHERE image_id=? ORDER BY address", (self.current_image["id"],)).fetchall()
        else:
            self.symbols = []

    def load_hw(self):
        if self.current_project:
            self.hw = self.con.execute("SELECT * FROM hardware_interfaces WHERE project_id=?", (self.current_project["id"],)).fetchall()
        else:
            self.hw = []

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        # Header
        if self.mode == "projects":
            title = " FREWB — Projects "
        elif self.mode == "images":
            title = f" FREWB — {self.current_project['name']} — Images "
        elif self.mode == "findings":
            title = f" FREWB — {Path(self.current_image['filename']).name} — Findings "
        elif self.mode == "symbols":
            title = f" FREWB — {Path(self.current_image['filename']).name} — Symbols "
        elif self.mode == "hw":
            title = f" FREWB — {self.current_project['name']} — Hardware "
        else:
            title = " FREWB "

        self.stdscr.addstr(0, 0, title.ljust(w), curses.color_pair(1) | curses.A_BOLD)

        # Content
        visible = h - 4
        items = self.get_current_items()

        for i in range(visible):
            idx = self.offset + i
            if idx >= len(items):
                break
            item = items[idx]
            line = self.format_item(item, self.mode)
            attr = curses.A_REVERSE if idx == self.selected else curses.A_NORMAL
            try:
                self.stdscr.addstr(i + 1, 0, line[:w-1], attr)
            except curses.error:
                pass

        # Help
        help_text = self.get_help()
        self.stdscr.addstr(h-2, 0, help_text[:w-1], curses.A_DIM)

        # Input line
        if self.input_mode:
            self.stdscr.addstr(h-1, 0, f"{self.input_prompt}{self.input_buffer}".ljust(w), curses.A_REVERSE)
        else:
            self.stdscr.addstr(h-1, 0, " " * w, curses.A_DIM)

        self.stdscr.refresh()

    def get_current_items(self):
        if self.mode == "projects":
            return self.projects
        elif self.mode == "images":
            return self.images
        elif self.mode == "findings":
            return self.findings
        elif self.mode == "symbols":
            return self.symbols
        elif self.mode == "hw":
            return self.hw
        return []

    def format_item(self, item, mode):
        if mode == "projects":
            return f"  {item['name']:<30} {item['target_device']:<20} {item['soc']:<15} {item['updated_at'][:19]}"
        elif mode == "images":
            sha = item['sha256'][:16] if item['sha256'] else "N/A"
            return f"  {Path(item['filename']).name:<40} {sha}  {item['arch']:<8} {item['size']}B"
        elif mode == "findings":
            return f"  0x{item['offset']:08X}  {item['type']:<20} {item['description'][:60]}"
        elif mode == "symbols":
            return f"  0x{item['address']:<12} {item['name']:<40} {item['type']}"
        elif mode == "hw":
            return f"  {item['interface_type']:<10} {item['protocol']:<10} pins={item['pins'] or 'N/A':<10} baud={item['baudrate'] or 'N/A'}"
        return str(item)

    def get_help(self):
        if self.mode == "projects":
            return "↑↓ Nav | Enter Open | n New | d Delete | q Quit"
        elif self.mode == "images":
            return "↑↓ Nav | Enter Analyze | a Add | d Delete | b Back | q Quit"
        elif self.mode in ("findings", "symbols", "hw"):
            return "↑↓ Nav | b Back | q Quit"
        return "q Quit"

    def handle_key(self, key):
        if self.input_mode:
            if key in (curses.KEY_ENTER, 10, 13):
                if self.input_callback:
                    self.input_callback(self.input_buffer)
                self.input_mode = False
                self.input_buffer = ""
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                self.input_buffer = self.input_buffer[:-1]
            elif key == 27:  # ESC
                self.input_mode = False
                self.input_buffer = ""
            elif 32 <= key <= 126:
                self.input_buffer += chr(key)
            return

        items = self.get_current_items()

        if key == curses.KEY_UP and self.selected > 0:
            self.selected -= 1
            if self.selected < self.offset:
                self.offset = self.selected
        elif key == curses.KEY_DOWN and self.selected < len(items) - 1:
            self.selected += 1
            if self.selected >= self.offset + self.stdscr.getmaxyx()[0] - 4:
                self.offset = self.selected - self.stdscr.getmaxyx()[0] + 5
        elif key in (curses.KEY_ENTER, 10, 13):
            self.on_enter()
        elif key == ord('q'):
            if self.mode == "projects":
                return False  # Quit
            elif self.mode in ("images", "findings", "symbols", "hw"):
                self.go_back()
        elif key == ord('b') and self.mode != "projects":
            self.go_back()
        elif key == ord('n') and self.mode == "projects":
            self.prompt_input("New project name: ", self.create_project)
        elif key == ord('a') and self.mode == "images":
            self.prompt_input("Firmware file path: ", self.add_image)
        elif key == ord('d'):
            self.delete_current()
        elif key == ord('r') and self.mode in ("projects", "images"):
            self.generate_report()

        return True

    def on_enter(self):
        items = self.get_current_items()
        if not items or self.selected >= len(items):
            return

        item = items[self.selected]

        if self.mode == "projects":
            self.current_project = item
            self.mode = "images"
            self.selected = 0
            self.offset = 0
            self.load_images()
        elif self.mode == "images":
            self.current_image = item
            self.mode = "findings"
            self.selected = 0
            self.offset = 0
            self.load_findings()
            self.load_symbols()
            self.load_hw()
        elif self.mode == "findings":
            # Show detail
            pass
        elif self.mode == "symbols":
            pass
        elif self.mode == "hw":
            pass

    def go_back(self):
        if self.mode == "images":
            self.mode = "projects"
            self.current_project = None
            self.load_projects()
        elif self.mode in ("findings", "symbols"):
            self.mode = "images"
            self.current_image = None
            self.load_images()
        elif self.mode == "hw":
            self.mode = "images"
            self.load_hw()
        self.selected = 0
        self.offset = 0

    def prompt_input(self, prompt, callback):
        self.input_mode = True
        self.input_prompt = prompt
        self.input_callback = callback
        curses.curs_set(1)
        curses.echo()

    def create_project(self, name):
        if not name.strip():
            return
        parts = name.split()
        proj_name = parts[0]
        device = parts[1] if len(parts) > 1 else ""
        soc = parts[2] if len(parts) > 2 else ""
        flash = parts[3] if len(parts) > 3 else ""
        cur = self.con.execute(
            "INSERT INTO projects (name, path, target_device, soc, flash_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (proj_name, str(WORK_DIR / proj_name), device, soc, flash, datetime.now().isoformat(), datetime.now().isoformat())
        )
        self.con.commit()
        self.load_projects()
        curses.curs_set(0)
        curses.noecho()

    def add_image(self, path):
        if not path.strip() or not self.current_project:
            curses.curs_set(0)
            curses.noecho()
            return
        filepath = Path(path.strip())
        if not filepath.exists():
            self.show_message("File not found")
            curses.curs_set(0)
            curses.noecho()
            return
        import hashlib
        sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()
        size = filepath.stat().st_size
        import magic
        mime = magic.from_file(str(filepath), mime=True)
        self.con.execute(
            "INSERT INTO firmware_images (project_id, filename, sha256, size, mime_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (self.current_project["id"], filepath.name, sha256, size, mime, datetime.now().isoformat())
        )
        self.con.commit()
        self.load_images()
        curses.curs_set(0)
        curses.noecho()

    def delete_current(self):
        items = self.get_current_items()
        if not items or self.selected >= len(items):
            return
        item = items[self.selected]
        if self.mode == "projects":
            self.con.execute("DELETE FROM projects WHERE id=?", (item["id"],))
            self.load_projects()
        elif self.mode == "images":
            self.con.execute("DELETE FROM firmware_images WHERE id=?", (item["id"],))
            self.load_images()
        if self.selected >= len(self.get_current_items()):
            self.selected = max(0, len(self.get_current_items()) - 1)

    def generate_report(self):
        if self.mode == "projects" and self.current_project:
            pid = self.current_project["id"]
        elif self.mode == "images" and self.current_image:
            pid = self.current_image["project_id"]
        else:
            return
        self.show_message("Generating report...")
        result = subprocess.run([sys.executable, "-m", "frewb", "report", str(pid)], capture_output=True, text=True)
        self.show_message(f"Report: {result.stdout.strip() or result.stderr.strip()}")

    def show_message(self, msg):
        h, w = self.stdscr.getmaxyx()
        self.stdscr.addstr(h-2, 0, msg[:w-1].ljust(w), curses.color_pair(2) | curses.A_BOLD)
        self.stdscr.refresh()
        time.sleep(2)

    def run(self):
        self.load_projects()
        while True:
            self.draw()
            key = self.stdscr.getch()
            if not self.handle_key(key):
                break

def main(stdscr):
    app = FrewbTUI(stdscr)
    app.run()

if __name__ == "__main__":
    if not DB_PATH.exists():
        print("Database not found. Run 'frewb init' first.")
        sys.exit(1)
    curses.wrapper(main)
