import os
import re
import sys
import ctypes
import threading
import tkinter as tk
from ctypes import wintypes
import msvcrt
import threading
import time

# Chargement des DLL Windows
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

# Structures pour la console
class _COORD(ctypes.Structure):
    _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

class SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", wintypes.SHORT),
                ("Top", wintypes.SHORT),
                ("Right", wintypes.SHORT),
                ("Bottom", wintypes.SHORT)]

class CONSOLE_SCREEN_BUFFER_INFOEX(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwSize", _COORD),
        ("dwCursorPosition", _COORD),
        ("wAttributes", wintypes.WORD),
        ("srWindow", SMALL_RECT),
        ("dwMaximumWindowSize", _COORD),
        ("wPopupAttributes", wintypes.WORD),
        ("bFullscreenSupported", wintypes.BOOL),
        ("ColorTable", wintypes.DWORD * 16)
    ]

class CONSOLE_FONT_INFOEX(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("nFont", wintypes.DWORD),
        ("dwFontSize", _COORD),
        ("FontFamily", wintypes.UINT),
        ("FontWeight", wintypes.UINT),
        ("FaceName", wintypes.WCHAR * 32)
    ]

# Constante simulée
BAYLIFE_SCROLL_DOWN = False
slider_widget = None  # variable globale pour le slider tkinter

# Classe de données principale
class BayLife:
    html_content = ""
    first_launch = True
    show_console = True
    hConsole = None
    console_window = None
    image_data = []
    buffer_width = 0
    buffer_height = 0
    char_width_px = 8
    char_height_px = 16
    horizontal_scroll_pos = 0
    vertical_scroll_pos = 0

def watch_console_resize():
    prev_width = 0
    prev_height = 0

    while True:
        info = CONSOLE_SCREEN_BUFFER_INFOEX()
        info.cbSize = ctypes.sizeof(info)
        if kernel32.GetConsoleScreenBufferInfoEx(BayLife.hConsole, ctypes.byref(info)):
            width = info.srWindow.Right - info.srWindow.Left + 1
            height = info.srWindow.Bottom - info.srWindow.Top + 1
            if width != prev_width or height != prev_height:
                prev_width, prev_height = width, height
                # On redessine l'image avec le scroll
                os.system('cls')  # nettoie la console
                display_image_data()

                # Met à jour le slider s'il existe
                global slider_widget
                if slider_widget:
                    slider_widget.config(to=max(0, BayLife.buffer_width - 80),
                                         length=BayLife.buffer_width * 8)
                    slider_widget.set(BayLife.horizontal_scroll_pos)
        time.sleep(0.2)  # évite de trop utiliser le CPU


def get_screen_size_pixels():
    return user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)

def get_console_font_size():
    cfi = CONSOLE_FONT_INFOEX()
    cfi.cbSize = ctypes.sizeof(CONSOLE_FONT_INFOEX)
    if kernel32.GetCurrentConsoleFontEx(BayLife.hConsole, False, ctypes.byref(cfi)):
        return cfi.dwFontSize.X, cfi.dwFontSize.Y
    return 8, 16

def initialize_console():
    if BayLife.hConsole is None:
        kernel32.AllocConsole()
        BayLife.console_window = kernel32.GetConsoleWindow()
        sys.stdin = open('CONIN$', 'r')
        sys.stdout = open('CONOUT$', 'w', buffering=1, encoding='utf-8', errors='replace')
        sys.stderr = open('CONOUT$', 'w', buffering=1, encoding='utf-8', errors='replace')
        BayLife.hConsole = kernel32.GetStdHandle(-11)

        mode = wintypes.DWORD()
        kernel32.GetConsoleMode(BayLife.hConsole, ctypes.byref(mode))
        mode.value |= 0x0004
        kernel32.SetConsoleMode(BayLife.hConsole, mode)

        cfi = CONSOLE_FONT_INFOEX()
        cfi.cbSize = ctypes.sizeof(CONSOLE_FONT_INFOEX)
        cfi.dwFontSize = _COORD(0, 14)
        cfi.FontFamily = 54
        cfi.FontWeight = 400
        cfi.FaceName = "Lucida Console"
        kernel32.SetCurrentConsoleFontEx(BayLife.hConsole, False, ctypes.byref(cfi))

        BayLife.char_width_px, BayLife.char_height_px = get_console_font_size()
        kernel32.SetConsoleTitleW("BayLife Image Viewer")

def ensure_console_buffer(min_width, min_height):
    if not BayLife.hConsole:
        return False
    info = CONSOLE_SCREEN_BUFFER_INFOEX()
    info.cbSize = ctypes.sizeof(info)
    if not kernel32.GetConsoleScreenBufferInfoEx(BayLife.hConsole, ctypes.byref(info)):
        return False
    desired_width = max(min_width, info.dwSize.X)
    desired_height = max(min_height, info.dwSize.Y)
    if desired_width != info.dwSize.X or desired_height != info.dwSize.Y:
        info.dwSize.X = desired_width
        info.dwSize.Y = desired_height
        if not kernel32.SetConsoleScreenBufferInfoEx(BayLife.hConsole, ctypes.byref(info)):
            return False
    return True

def adjust_console_window_size():
    info = CONSOLE_SCREEN_BUFFER_INFOEX()
    info.cbSize = ctypes.sizeof(info)
    if not kernel32.GetConsoleScreenBufferInfoEx(BayLife.hConsole, ctypes.byref(info)):
        return False

    screen_w_px, screen_h_px = get_screen_size_pixels()
    max_win_cols = (screen_w_px - 10) // BayLife.char_width_px
    max_win_rows = (screen_h_px - 10) // BayLife.char_height_px
    window_width = min(max_win_cols, info.dwSize.X)
    window_height = min(max_win_rows, info.dwSize.Y)

    h_pos = BayLife.horizontal_scroll_pos
    v_pos = BayLife.vertical_scroll_pos
    h_pos = max(0, min(h_pos, info.dwSize.X - window_width))
    v_pos = max(0, min(v_pos, info.dwSize.Y - window_height))

    BayLife.horizontal_scroll_pos = h_pos
    BayLife.vertical_scroll_pos = v_pos

    info.srWindow.Left = h_pos
    info.srWindow.Top = v_pos
    info.srWindow.Right = h_pos + window_width - 1
    info.srWindow.Bottom = v_pos + window_height - 1

    return kernel32.SetConsoleScreenBufferInfoEx(BayLife.hConsole, ctypes.byref(info))

def hex_to_ansi_color(hex_color):
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    return f"\033[38;2;{r};{g};{b}m"

def parse_html_to_image_data():
    BayLife.image_data = []
    black = "\033[38;2;0;0;0m"
    max_width = 0
    for line in BayLife.html_content.split('\n'):
        line_width = sum(len(match.group(2)) for match in re.finditer(r'<b style="color:#([0-9A-Fa-f]{6})">([01]+)</b>', line))
        max_width = max(max_width, line_width)

    for line in BayLife.html_content.split('\n'):
        current_line = []
        for match in re.finditer(r'<b style="color:#([0-9A-Fa-f]{6})">([01]+)</b>', line):
            color = hex_to_ansi_color(match.group(1))
            for c in match.group(2):
                current_line.append({'c': c, 'color': color})
        BayLife.image_data.append(current_line)

    BayLife.buffer_width = max_width
    BayLife.buffer_height = len(BayLife.image_data)

def display_image_data():
    if not ensure_console_buffer(BayLife.buffer_width + 5, BayLife.buffer_height + 1):
        return
    if not adjust_console_window_size():
        return

    os.system("cls")
    info = CONSOLE_SCREEN_BUFFER_INFOEX()
    info.cbSize = ctypes.sizeof(info)
    kernel32.GetConsoleScreenBufferInfoEx(BayLife.hConsole, ctypes.byref(info))
    window_width = info.srWindow.Right - info.srWindow.Left + 1
    h_pos = BayLife.horizontal_scroll_pos
    for line in BayLife.image_data:
        visible_line = line[h_pos:h_pos + window_width]
        current_color = None
        for cc in visible_line:
            if cc['color'] != current_color:
                print(cc['color'], end='')
                current_color = cc['color']
            print(cc['c'], end='')
        print()
    print("\033[0m")

def load_html_from_file():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baylife.html")
    try:
        with open(html_path, 'r', encoding='utf-8') as file:
            BayLife.html_content = file.read()
            parse_html_to_image_data()
    except FileNotFoundError:
        BayLife.html_content = ""
        BayLife.image_data = []

def copy_to_clipboard():
    # Construit uniquement les caractères 0 et 1
    output = ""
    for line in BayLife.image_data:
        output += ''.join(cc['c'] for cc in line) + "\n"

    # Copie dans le presse-papiers avec Tkinter
    dummy = tk.Tk()
    dummy.withdraw()
    dummy.clipboard_clear()
    dummy.clipboard_append(output)
    dummy.update()
    dummy.destroy()

def show_slider_window():
    global slider_widget

    def on_slide(val):
        BayLife.horizontal_scroll_pos = int(float(val))
        display_image_data()

    root = tk.Tk()
    root.title("BayLife Scroll")
    root.geometry(f"{BayLife.buffer_width * 8}x100+200+800")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    copy_btn = tk.Button(frame, text="📋 Copier dans le presse-papiers", command=copy_to_clipboard)
    copy_btn.pack()

    slider_widget = tk.Scale(frame,
                             from_=0,
                             to=max(0, BayLife.buffer_width - 80),
                             orient="horizontal",
                             length=BayLife.buffer_width * 8,
                             command=on_slide)
    slider_widget.set(BayLife.horizontal_scroll_pos)
    slider_widget.pack()

    root.mainloop()


def baylife_image():
    if BayLife.first_launch:
        initialize_console()
        load_html_from_file()
        BayLife.first_launch = False
    if BayLife.show_console:
        display_image_data()
        threading.Thread(target=show_slider_window, daemon=True).start()

if __name__ == "__main__":
    baylife_image()
    threading.Thread(target=watch_console_resize, daemon=True).start()
    if BayLife.show_console:
        msvcrt.getch()
