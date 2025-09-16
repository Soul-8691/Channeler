import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import struct

# Constants
STRING_BASE = 0x15BF724
NUM_STRINGS = 2098

POINTER_TABLES = {
    "Card Names": 0x15BB594,
    "Card Descriptions": 0x15BD65C,
}

current_file = None
current_pointer_offset = None
current_table_name = None
cached_names = None  # For labeling descriptions


# ============================
#  Binary Helpers
# ============================

def read_strings(filename, pointer_offset):
    strings = []
    with open(filename, "rb") as f:
        f.seek(pointer_offset)
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


def find_free_space(f, size):
    f.seek(STRING_BASE)
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


def edit_string(filename, pointer_offset, index, new_text):
    with open(filename, "r+b") as f:
        f.seek(pointer_offset + index * 4)
        rel = struct.unpack("<I", f.read(4))[0]
        abs_offset = STRING_BASE + rel

        f.seek(abs_offset)
        old_bytes = bytearray()
        while True:
            b = f.read(1)
            if b == b"\x00" or not b:
                break
            old_bytes.append(b[0])

        new_bytes = new_text.encode("ascii") + b"\x00"

        if len(new_bytes) <= len(old_bytes) + 1:
            padded = new_bytes + b"\x00" * (len(old_bytes) + 1 - len(new_bytes))
            f.seek(abs_offset)
            f.write(padded)
        else:
            free_offset = find_free_space(f, len(new_bytes))
            if free_offset is None:
                raise RuntimeError("No free space available")
            f.seek(free_offset)
            f.write(new_bytes)
            new_rel = free_offset - STRING_BASE
            f.seek(pointer_offset + index * 4)
            f.write(struct.pack("<I", new_rel))


# ============================
#  Tkinter GUI
# ============================

def open_file():
    global current_file, current_pointer_offset, current_table_name, cached_names

    filename = filedialog.askopenfilename(
        title="Open Binary File",
        filetypes=[("Binary files", "*.*")]
    )
    if not filename:
        return

    choice = simpledialog.askstring(
        "Select Table",
        "Type 'names' for Card Names or 'descriptions' for Card Descriptions:"
    )
    if not choice:
        return

    choice = choice.lower()
    if choice.startswith("name"):
        pointer_offset = POINTER_TABLES["Card Names"]
        table_name = "Card Names"
    elif choice.startswith("desc"):
        pointer_offset = POINTER_TABLES["Card Descriptions"]
        table_name = "Card Descriptions"
    else:
        messagebox.showwarning("Invalid Choice", "Please enter 'names' or 'descriptions'.")
        return

    try:
        strings = read_strings(filename, pointer_offset)
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    current_file = filename
    current_pointer_offset = pointer_offset
    current_table_name = table_name

    # Preload card names if we’re in descriptions mode
    if table_name == "Card Descriptions":
        cached_names = read_strings(filename, POINTER_TABLES["Card Names"])
    else:
        cached_names = None

    refresh_listbox(strings)
    root.title(f"Binary String Editor - {table_name}")


def refresh_listbox(strings):
    listbox.delete(0, tk.END)
    if current_table_name == "Card Descriptions" and cached_names:
        for name, desc in zip(cached_names, strings):
            listbox.insert(tk.END, f"{name} – {desc}")
    else:
        for s in strings:
            listbox.insert(tk.END, s)


def edit_selected():
    global current_file, current_pointer_offset

    if current_file is None or current_pointer_offset is None:
        messagebox.showwarning("No file", "Please open a file and select a table first.")
        return

    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a string to edit.")
        return

    index = selection[0]
    # Use only the actual string value for editing
    if current_table_name == "Card Descriptions" and cached_names:
        old_text = listbox.get(index).split(" – ", 1)[1]
    else:
        old_text = listbox.get(index)

    new_text = simpledialog.askstring("Edit String", f"Edit string #{index}:", initialvalue=old_text)
    if new_text is None:
        return

    try:
        edit_string(current_file, current_pointer_offset, index, new_text)
        strings = read_strings(current_file, current_pointer_offset)
        refresh_listbox(strings)
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
listbox = tk.Listbox(frame, selectmode=tk.SINGLE, yscrollcommand=scrollbar.set, width=100, height=30)
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

root.mainloop()
