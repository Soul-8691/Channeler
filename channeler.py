import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import struct
import os

# -----------------------
# Constants / Globals
# -----------------------
STRING_BASE = 0x15BF724
NUM_STRINGS = 2098

POINTER_TABLES = {
    "Card Names": 0x15BB594,
    "Card Descriptions": 0x15BD65C,
}

SCRIPTS_TABLE_OFFSET = 0x004B2F0
SCRIPTS_TABLE_END = 0x004C6AB

current_file = None
current_pointer_offset = None
current_table_name = None
cached_names = None
scripts_data = None


# -----------------------
# Binary helper functions
# -----------------------
def _file_len(filename):
    return os.path.getsize(filename)


def read_strings(filename, pointer_offset):
    strings = []
    with open(filename, "rb") as f:
        f.seek(pointer_offset)
        relative_offsets = [struct.unpack("<I", f.read(4))[0] for _ in range(NUM_STRINGS)]
        for rel in relative_offsets:
            abs_offset = STRING_BASE + rel
            if abs_offset < 0 or abs_offset >= _file_len(filename):
                strings.append("<invalid ptr>")
                continue
            f.seek(abs_offset)
            chars = []
            while True:
                b = f.read(1)
                if not b or b == b"\x00":
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
        if not b:
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
        old_body = bytearray()
        while True:
            b = f.read(1)
            if not b or b == b"\x00":
                break
            old_body.append(b[0])

        new_body = new_text.encode("ascii")
        new_bytes = new_body + b"\x00"

        if len(new_bytes) <= len(old_body) + 1:
            padded = new_bytes + b"\x00" * ((len(old_body) + 1) - len(new_bytes))
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

# Load card names (not numeric IDs)
def load_card_name_map(txt_filename):
    """
    Returns a list of card names; first entry corresponds to 4007, etc.
    """
    with open(txt_filename, "r", encoding="utf-8") as f:
        names = [line.strip() for line in f if line.strip()]
    return names

# -----------------------
# Scripts parsing
# -----------------------
def read_scripts_table(filename, table_offset, table_end, card_name_map):
    """
    Parse scripts from table_offset up to table_end.
    Multiple 4-byte card IDs can appear back-to-back, sharing the same script bytes.
    Only card IDs >= 4007 <= 6655 are included.
    Maps each card ID to a name from card_name_map (first entry corresponds to 4007).
    """
    entries = []
    with open(filename, "rb") as f:
        pos = table_offset
        index = 0
        while pos + 4 <= table_end:
            f.seek(pos)
            header = f.read(4)
            if len(header) < 4:
                break
            card_id = struct.unpack("<I", header)[0]

            # Skip invalid IDs
            if card_id < 4007 or card_id > 6655:
                pos += 2
                continue

            # Read script body until 0xE0
            body_start = pos + 4
            f.seek(body_start)
            body = []
            while body_start + len(body) < table_end:
                b = f.read(1)
                if not b:
                    break
                val = b[0]
                body.append(val)
                if val == 0xE0:
                    break

            # Collect all consecutive card IDs sharing this body
            # Collect all consecutive card IDs sharing this body
            ids_for_body = []
            temp_pos = pos
            while temp_pos + 4 <= body_start:
                f.seek(temp_pos)
                peek = f.read(4)
                if len(peek) < 4:
                    break
                peek_id = struct.unpack("<I", peek)[0]
                if peek_id < 4007:
                    break
                # Map to text file name
                name_idx = peek_id - 4007
                if name_idx >= len(card_name_map):
                    mapped_name = f"<Unknown {peek_id}>"
                else:
                    mapped_name = card_name_map[name_idx]
                ids_for_body.append(mapped_name)
                temp_pos += 4
                if temp_pos >= body_start:
                    break

            # Add an entry for each mapped name pointing to the same body
            for mapped_name in ids_for_body:
                entries.append({
                    'index': index,
                    'card_id': card_id,
                    'name': mapped_name,
                    'bytes': body,
                    'start': pos
                })
                index += 1

            # Advance pos past the body
            pos = body_start + len(body)
            if pos >= table_end:
                break

    return entries

# -----------------------
# Tkinter UI Functions
# -----------------------
def open_file():
    global current_file, current_pointer_offset, current_table_name, cached_names, scripts_data

    filename = filedialog.askopenfilename(title="Open Binary File", filetypes=[("Binary files", "*.*")])
    if not filename:
        return

    choice = simpledialog.askstring(
        "Select Mode",
        "Type 'names', 'descriptions', or 'scripts':"
    )
    if not choice:
        return
    choice = choice.strip().lower()

    if choice.startswith("name"):
        pointer_offset = POINTER_TABLES["Card Names"]
        current_file = filename
        current_pointer_offset = pointer_offset
        current_table_name = "Card Names"
        cached_names = None
        scripts_data = None
        strings = read_strings(filename, pointer_offset)
        left_listbox.config(selectmode=tk.SINGLE)
        refresh_strings_in_listbox(strings)

    elif choice.startswith("desc"):
        pointer_offset = POINTER_TABLES["Card Descriptions"]
        current_file = filename
        current_pointer_offset = pointer_offset
        current_table_name = "Card Descriptions"
        cached_names = read_strings(filename, POINTER_TABLES["Card Names"])
        scripts_data = None
        strings = read_strings(filename, pointer_offset)
        left_listbox.config(selectmode=tk.SINGLE)
        refresh_descriptions_in_listbox(strings, cached_names)

    elif choice.startswith("script"):
        current_file = filename
        current_pointer_offset = None
        current_table_name = "Scripts"
        cached_names = None
        scripts_data = read_scripts_table(filename, SCRIPTS_TABLE_OFFSET, SCRIPTS_TABLE_END, load_card_name_map('Card_IDs.txt'))
        left_listbox.config(selectmode=tk.EXTENDED)
        refresh_scripts_listbox(scripts_data)
        right_listbox.delete(0, tk.END)

    else:
        messagebox.showwarning("Invalid Choice", "Enter 'names', 'descriptions', or 'scripts'.")
        return

    root.title(f"Binary String Editor - {current_table_name}")


def refresh_strings_in_listbox(strings):
    left_listbox.delete(0, tk.END)
    for s in strings:
        left_listbox.insert(tk.END, s)


def refresh_descriptions_in_listbox(descriptions, names):
    left_listbox.delete(0, tk.END)
    for n, d in zip(names, descriptions):
        left_listbox.insert(tk.END, f"{n} – {d}")


def refresh_scripts_listbox(scripts):
    left_listbox.delete(0, tk.END)
    for i, entry in enumerate(scripts):
        # When populating the left listbox for scripts:
        left_listbox.insert(tk.END, f"{i:04d}: {entry['name']} @0x{entry['start']:06X}")


def on_left_select(event):
    if current_table_name == "Scripts":
        sel = left_listbox.curselection()
        right_listbox.delete(0, tk.END)
        if not sel:
            return
        for idx in sel:
            entry = scripts_data[idx]
            header = f"Script #{entry['index']} - {entry['name']} @0x{entry['start']:06X}"
            right_listbox.insert(tk.END, header)
            right_listbox.insert(tk.END, "-" * len(header))
            for i, b in enumerate(entry['bytes']):
                right_listbox.insert(tk.END, f"[{i:03d}] {b} (0x{b:02X})")
            right_listbox.insert(tk.END, "")
    else:
        sel = left_listbox.curselection()
        if not sel:
            edit_entry_var.set("")
            return
        idx = sel[0]
        if current_table_name == "Card Descriptions" and cached_names:
            entry_text = left_listbox.get(idx)
            if " – " in entry_text:
                _, desc = entry_text.split(" – ", 1)
                edit_entry_var.set(desc)
            else:
                edit_entry_var.set(entry_text)
        else:
            edit_entry_var.set(left_listbox.get(idx))


def edit_selected():
    global current_file, current_pointer_offset
    if current_file is None or current_table_name is None:
        messagebox.showwarning("No file", "Open a file first.")
        return
    if current_table_name == "Scripts":
        messagebox.showinfo("Scripts mode", "Editing scripts is not supported here.")
        return
    selection = left_listbox.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Select a string to edit.")
        return
    index = selection[0]
    if current_table_name == "Card Descriptions" and cached_names:
        old_text = left_listbox.get(index).split(" – ", 1)[1]
    else:
        old_text = left_listbox.get(index)
    new_text = simpledialog.askstring("Edit String", f"Edit string #{index}:", initialvalue=old_text)
    if new_text is None:
        return
    try:
        edit_string(current_file, current_pointer_offset, index, new_text)
        if current_table_name == "Card Descriptions":
            strings = read_strings(current_file, current_pointer_offset)
            cached = read_strings(current_file, POINTER_TABLES["Card Names"])
            refresh_descriptions_in_listbox(strings, cached)
        else:
            strings = read_strings(current_file, current_pointer_offset)
            refresh_strings_in_listbox(strings)
        left_listbox.selection_set(index)
        left_listbox.see(index)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to edit string: {e}")


def save_file_as():
    if current_file is None:
        messagebox.showwarning("No file", "Open and edit a file first.")
        return
    out = filedialog.asksaveasfilename(title="Save As", defaultextension=".bin", filetypes=[("Binary files", "*.*")])
    if not out:
        return
    with open(current_file, "rb") as inf, open(out, "wb") as outf:
        outf.write(inf.read())
    messagebox.showinfo("Saved", f"Saved copy to {out}")


# -----------------------
# Build UI
# -----------------------
root = tk.Tk()
root.title("Binary String Editor")

panes = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
panes.pack(fill=tk.BOTH, expand=True)

left_frame = tk.Frame(panes)
left_listbox = tk.Listbox(left_frame, selectmode=tk.SINGLE, width=60, height=30)
left_scroll = tk.Scrollbar(left_frame, orient=tk.VERTICAL, command=left_listbox.yview)
left_listbox.config(yscrollcommand=left_scroll.set)
left_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
left_scroll.pack(side=tk.RIGHT, fill=tk.Y)
left_listbox.bind("<<ListboxSelect>>", on_left_select)
panes.add(left_frame)

right_frame = tk.Frame(panes)
right_listbox = tk.Listbox(right_frame, width=60, height=30)
right_scroll = tk.Scrollbar(right_frame, orient=tk.VERTICAL, command=right_listbox.yview)
right_listbox.config(yscrollcommand=right_scroll.set)
right_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
right_scroll.pack(side=tk.RIGHT, fill=tk.Y)
panes.add(right_frame)

bottom_frame = tk.Frame(root)
bottom_frame.pack(fill=tk.X)
edit_entry_var = tk.StringVar()
edit_entry = tk.Entry(bottom_frame, textvariable=edit_entry_var, width=80)
edit_entry.pack(side=tk.LEFT, padx=4, pady=4, fill=tk.X, expand=True)
apply_btn = tk.Button(bottom_frame, text="Apply Edit", command=edit_selected)
apply_btn.pack(side=tk.RIGHT, padx=4)

menu = tk.Menu(root)
root.config(menu=menu)
file_menu = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Open...", command=open_file)
file_menu.add_command(label="Save As...", command=save_file_as)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

edit_menu = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="Edit", menu=edit_menu)
edit_menu.add_command(label="Edit Selected...", command=edit_selected)

root.mainloop()
