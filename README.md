# frewb — Firmware RE Workbench

**Единая автономная среда для реверс-инжиниринга прошивок на Android/Termux.**  
Нет аналогов: объединяет БД проекта, статический анализ (binwalk/strings/entropy), QEMU-эмуляцию, железные интерфейсы (UART/GPIO/SPI/JTAG) и генерацию отчётов — в одном TUI.

## Возможности

| Модуль | Что делает |
|--------|------------|
| **Projects DB** | SQLite: проекты, образы, находки, символы, HW-интерфейсы |
| **Static Analysis** | binwalk (рекурсивно), strings (с offset), entropy, arch detection, авто-экстракция |
| **QEMU User-mode** | Запуск бинарей под arm/aarch64/mips/x86 с rootfs из прошивки |
| **Hardware I/F** | UART multi-baud скан, GPIO mapping, SPI dump (CH341A), JTAG (openocd) |
| **Reporting** | Markdown-отчёт: проект, HW, образы, находки по типам, символы |
| **TUI** | Интерактивный curses-интерфейс для навигации по проекту |

## Установка

```bash
# Зависимости (Termux)
pkg install python binwalk file xxd strings qemu-common binutils magic

# Python deps
pip install python-magic

# Клонирование
git clone https://github.com/Xnode-sh/frewb ~/frewb
cd ~/frewb
chmod +x frewb frewb.py frewb_tui.py

# Опционально: flashrom, openocd, arm-none-eabi-gcc (если есть в репозиториях)
```

## Быстрый старт (VM1920)

```bash
# 1. Создать проект
frewb init vm1920 "Volia VM1920" "BCM75831" "SPI MX25L3205"

# 2. Добавить дамп SPI
frewb add vm1920 spi_dump.bin

# 3. Полный статический анализ
frewb analyze 1

# 4. Сканировать UART (подключен CH340 к J10)
frewb uart 1 /dev/ttyUSB0

# 5. Записать GPIO mapping (пример: 14=TX, 15=RX, 16=GND)
frewb gpio 1 "14:TX,15:RX,16:GND"

# 6. Дамп SPI через CH341A (если ещё не делали)
frewb spi 1 MX25L3205

# 7. Запустить бинарь из прошивки под QEMU
frewb emulate 1 ./extracted_1/squashfs-root/bin/busybox --help

# 8. Генерация отчёта
frewb report 1

# 9. TUI для интерактивной работы
python3 frewb_tui.py
```

## CLI команды

```
frewb init <name> [device] [soc] [flash]     Создать проект
frewb add <project> <firmware.bin>           Добавить образ
frewb analyze <image_id>                     Статический анализ
frewb emulate <image_id> <binary> [args]     QEMU user-mode
frewb uart <project_id> [/dev/ttyUSB0]       UART multi-baud scan
frewb gpio <project_id> <pin:func,...>       GPIO mapping
frewb spi <project_id> [chip]                SPI dump via CH341A
frewb report <project_id> [out.md]           Markdown report
frewb list                                   Список проектов
```

## TUI навигация

```
Projects:  ↑↓ Enter=open  n=new  d=delete  q=quit
Images:    ↑↓ Enter=analyze  a=add  d=delete  b=back
Findings:  ↑↓  b=back  (фильтр по типам: bootloader, kernel, fs, crypto, strings...)
Symbols:   ↑↓  b=back
HW:        ↑↓  b=back
```

## Структура данных

```
~/frewb/
├── frewb.py          # Core logic
├── frewb_tui.py      # Curses TUI
├── frewb/            # Python package
├── frewb.db          # SQLite DB
├── work/             # Извлеченные ФС, дампы
│   ├── extracted_<id>/
│   └── spi_dump_<id>_<ts>.bin
└── tools/            # Скрипты/бинарники
```

## Пример отчёта (Markdown)

```markdown
# Firmware RE Report: vm1920
**Device:** Volia VM1920  
**SoC:** BCM75831  
**Flash:** SPI MX25L3205

## Hardware Interfaces
- UART (UART) - pins=/dev/ttyUSB0 baud=115200 V=3.3
  - Response: CFE version 1.0.37-114.185...
- GPIO (GPIO) - pins=14:TX,15:RX,16:GND baud=N/A V=3.3

## Image: spi_dump.bin
- SHA256: `a1b2c3d4...`
- Arch: ARM (little)
- Entry: 0x80010000

### Bootloader (1)
- 0x00000000: CFE version 1.0.37-114.185 BCM75831...

### Kernel (1)
- 0x00080000: Linux kernel ARM boot executable...

### Filesystem (1)
- 0x00200000: Squashfs filesystem, little endian...

### Crypto (2)
- 0x003F0000: Certificate: RSA 2048-bit...
- 0x003F1000: Private key: RSA...
```

## Для VM1920 (BCM75831)

1. **SPI дамп** → `frewb spi 1 MX25L3205` → `frewb add vm1920 spi_dump.bin` → `frewb analyze 1`
2. **Ищи в находках:** `CFE version`, `bootcmd=`, `bootargs=`, `console=ttyS0,115200`, `mtdparts=`
3. **UART J10** → `frewb uart 1 /dev/ttyUSB0` → ловишь CFE/BOLT консоль
4. **GPIO** → `frewb gpio 1 "14:TX,15:RX,16:GND"` (подстрой под реальную распиновку)
5. **Эмуляция** → если есть squashfs с busybox/sh: `frewb emulate 1 ./work/extracted_1/squashfs-root/bin/busybox sh`

## Требования

- Termux (Android 10+)
- Python 3.10+
- binwalk, file, xxd, strings, qemu-user-static
- python-magic (pip)
- Опционально: flashrom, openocd, arm-none-eabi-binutils, radare2/ghidra

## Лицензия

MIT