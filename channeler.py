import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import struct

# Constants
POINTER_OFFSET = 0x15BB594
STRING_BASE = 0x15BF724
NUM_STRINGS = 2098
FREE_SPACE_START = 0x161C2E3

# Read all strings
def read_strings(filename):
    strings = []
    with open(filename, "rb") as f:
        # Get relative offsets
        f.seek(POINTER_OFFSET)
        relative_offsets = [
            struct.unpack("<I", f.read(4))[0]
            for _ in range(NUM_STRINGS)
        ]
        for rel in relative_offsets:
            abs_offset = STRING_BASE + rel
            f.seek(abs_offset)
            chars = []
            while True:
                b = f.read(1)
                if b == b"\x00" or not b:
                    break
                try:
                    chars.append(b.decode("ascii"))
                except UnicodeDecodeError:
                    chars.append("?")
            strings.append("".join(chars))
    return strings

# Find free space region of required size (including terminating 00)
def find_free_space(f, size):
    f.seek(FREE_SPACE_START)
    free_count = 0
    start = None

    while True:
        b = f.read(1)
        if not b:  # EOF
            break
        if b == b"\x00":
            if start is None:
                start = f.tell() - 1
            free_count += 1
            if free_count >= size:
                return start + 1
        else:
            start = None
            free_count = 0
    return None

# Edit string at pointer index
def edit_string(filename, index, new_text):
    with open(filename, "r+b") as f:
        # Read pointer
        f.seek(POINTER_OFFSET + index * 4)
        rel = struct.unpack("<I", f.read(4))[0]
        abs_offset = STRING_BASE + rel

        # Read old string
        f.seek(abs_offset)
        old_bytes = bytearray()
        while True:
            b = f.read(1)
            if b == b"\x00" or not b:
                break
            old_bytes.append(b[0])

        new_bytes = new_text.encode("ascii") + b"\x00"

        if len(new_bytes) <= len(old_bytes) + 1:
            # Case 1: new string fits in old space (pad with 00s)
            padded = new_bytes + b"\x00" * (len(old_bytes) + 1 - len(new_bytes))
            f.seek(abs_offset)
            f.write(padded)

        else:
            # Case 2: need free space
            free_offset = find_free_space(f, len(new_bytes))
            if free_offset is None:
                raise RuntimeError("No free space available")

            # Write into free space
            f.seek(free_offset)
            f.write(new_bytes)

            # Update pointer
            new_rel = free_offset - STRING_BASE
            f.seek(POINTER_OFFSET + index * 4)
            f.write(struct.pack("<I", new_rel))

# Tkinter UI
def open_file():
    global current_file
    filename = filedialog.askopenfilename(
        title="Open Binary File",
        filetypes=[("Binary files", "*.*")]
    )
    if not filename:
        return
    try:
        strings = read_strings(filename)
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    current_file = filename
    listbox.delete(0, tk.END)
    for s in strings:
        listbox.insert(tk.END, s)

def edit_selected():
    if current_file is None:
        messagebox.showwarning("No file", "Please open a file first.")
        return

    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a string to edit.")
        return

    index = selection[0]
    old_text = listbox.get(index)

    new_text = simpledialog.askstring("Edit String", f"Edit string #{index}:", initialvalue=old_text)
    if new_text is None:
        return  # Cancel

    try:
        edit_string(current_file, index, new_text)
        # Refresh display
        strings = read_strings(current_file)
        listbox.delete(0, tk.END)
        for s in strings:
            listbox.insert(tk.END, s)
        listbox.selection_set(index)
        listbox.see(index)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Main app
root = tk.Tk()
root.title("Binary String Editor")

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
listbox = tk.Listbox(frame, selectmode=tk.SINGLE, yscrollcommand=scrollbar.set, width=80, height=30)
scrollbar.config(command=listbox.yview)

listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

menu = tk.Menu(root)
root.config(menu=menu)
file_menu = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Open...", command=open_file)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

edit_menu = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="Edit", menu=edit_menu)
edit_menu.add_command(label="Edit Selected...", command=edit_selected)

current_file = None

root.mainloop()
