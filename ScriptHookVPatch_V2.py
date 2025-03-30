import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox

# Configuration hex
HEX_PATTERN = [0x74, 0x2D, 0x4C, 0x8D, 0x4D]
REPLACEMENT = [0xEB, 0x2D, 0x4C, 0x8D, 0x4D]

def patch_file(file_path):
    """Applies the hex patch to the file."""
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
    """Opens the file selection dialog."""
    file_path = filedialog.askopenfilename(
        title="Select ScriptHookV.dll",
        filetypes=[("DLL Files", "*.dll"), ("All Files", "*.*")]
    )
    if file_path:
        patch_file(file_path)

def run_file_if_dropped(file_path):
    """Runs the patch if a file is passed as argument."""
    if os.path.isfile(file_path) and file_path.lower().endswith('.dll'):
        if not patch_file(file_path):
            input("Press Enter to exit...")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # File passed as command line argument
        run_file_if_dropped(sys.argv[1])
    else:
        root = tk.Tk()
        root.title("DLL Patcher - ScriptHookV")
        root.geometry("500x350")
        root.resizable(False, False)
        root.configure(bg="#f0f0f0")

        # Main frame
        main_frame = tk.Frame(root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Title
        tk.Label(main_frame,
                 text="ScriptHookV.dll Patcher",
                 font=("Arial", 14, "bold"),
                 bg="#f0f0f0").pack(pady=10)

        # Select file button
        tk.Button(main_frame,
                  text="Select a file",
                  command=select_file,
                  font=("Arial", 10),
                  width=20).pack(pady=10)

        # Instructions
        tk.Label(main_frame,
                 text="Select the .dll file to apply the patch.",
                 font=("Arial", 9),
                 bg="#f0f0f0").pack(pady=10)

        root.mainloop()
