import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
from ctypes import wintypes

HEX_PATTERN = [0x74, 0x2D, 0x4C, 0x8D, 0x4D]
REPLACEMENT = [0xEB, 0x2D, 0x4C, 0x8D, 0x4D]

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
WM_DROPFILES = 0x0233

class DROPFILES(ctypes.Structure):
    _fields_ = [("pFiles", wintypes.DWORD),
                ("pt", wintypes.POINT),
                ("fNC", wintypes.BOOL),
                ("fWide", wintypes.BOOL)]


def patch_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())

        found = False
        for i in range(len(data) - len(HEX_PATTERN) + 1):
            if all(data[i + j] == HEX_PATTERN[j] for j in range(len(HEX_PATTERN))):
                for j in range(len(REPLACEMENT)):
                    data[i + j] = REPLACEMENT[j]
                found = True
                break

        if found:
            new_path = os.path.join(os.path.dirname(file_path),
                                     "Patched_" + os.path.basename(file_path))
            with open(new_path, 'wb') as f:
                f.write(data)
            messagebox.showinfo("Success", f"Patched file created:\n{new_path}")
            return True
        else:
            messagebox.showwarning("Error", "Hex pattern not found.")
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed: {str(e)}")
        return False


def select_file():
    file_path = filedialog.askopenfilename(
        title="Select ScriptHookV.dll",
        filetypes=[("DLL Files", "*.dll"), ("All Files", "*.*")]
    )
    if file_path:
        patch_file(file_path)


class DnDApp:
    def __init__(self, root):
        self.root = root
        self.setup_ui()

    def setup_ui(self):
        self.root.title("DLL Patcher - ScriptHookV")
        self.root.geometry("500x350")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")

        main_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(main_frame,
                 text="ScriptHookV.dll Patcher",
                 font=("Arial", 14, "bold"),
                 bg="#f0f0f0").pack(pady=10)

        tk.Button(main_frame,
                  text="Select a file",
                  command=select_file,
                  font=("Arial", 10),
                  width=20).pack(pady=10)

        tk.Label(main_frame,
                 text="You can also select a file manually",
                 font=("Arial", 9),
                 bg="#f0f0f0").pack(pady=10)


def run_file_if_dropped(file_path):
    if os.path.isfile(file_path) and file_path.lower().endswith('.dll'):
        if not patch_file(file_path):
            input("Press Enter to exit...")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_file_if_dropped(sys.argv[1])
    else:
        root = tk.Tk()
        app = DnDApp(root)
        root.mainloop()
