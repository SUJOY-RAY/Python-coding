import hashlib
import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Encryption key length
KEY_LEN = 5

class EncrypterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Folder/File Encrypter")
        self.geometry("500x300")
        self.resizable(False, False)

        # Variables
        self.mode_var = tk.StringVar(value="encrypt")
        self.input_path_var = tk.StringVar()
        self.output_path_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.delete_original_var = tk.BooleanVar(value=False)

        self.create_widgets()

    def create_widgets(self):
        # Mode selection
        mode_frame = ttk.LabelFrame(self, text="Mode")
        mode_frame.pack(fill='x', padx=10, pady=5)
        ttk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt").pack(side='left', padx=10)
        ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt").pack(side='left')

        # Input path selection
        input_frame = ttk.Frame(self)
        input_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(input_frame, text="Input file/folder:").pack(anchor='w')
        input_entry = ttk.Entry(input_frame, textvariable=self.input_path_var, width=50)
        input_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(input_frame, text="Browse", command=self.browse_input).pack(side='left', padx=5)

        # Output path selection
        output_frame = ttk.Frame(self)
        output_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(output_frame, text="Output folder:").pack(anchor='w')
        output_entry = ttk.Entry(output_frame, textvariable=self.output_path_var, width=50)
        output_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(output_frame, text="Browse", command=self.browse_output).pack(side='left', padx=5)

        # Password entry
        password_frame = ttk.Frame(self)
        password_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(password_frame, text="Password:").pack(anchor='w')
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*")
        password_entry.pack(fill='x')

        # Delete original checkbox
        delete_chk = ttk.Checkbutton(self, text="Delete original after processing", variable=self.delete_original_var)
        delete_chk.pack(anchor='w', padx=10, pady=5)

        # Status and Run button
        self.status = tk.StringVar()
        ttk.Label(self, textvariable=self.status, foreground="blue").pack(fill='x', padx=10, pady=5)

        run_btn = ttk.Button(self, text="Run", command=self.run_encryption)
        run_btn.pack(pady=10)

    def browse_input(self):
        path = filedialog.askopenfilename(title="Select Input File")
        if not path:
            path = filedialog.askdirectory(title="Or Select Input Folder")
        if path:
            self.input_path_var.set(path)

    def browse_output(self):
        path = filedialog.askdirectory(title="Select Output Folder")
        if path:
            self.output_path_var.set(path)

    def run_encryption(self):
        mode = self.mode_var.get()
        input_path = self.input_path_var.get()
        output_path = self.output_path_var.get()
        password = self.password_var.get()
        delete_original = self.delete_original_var.get()

        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("Error", "Invalid input path.")
            return
        if not output_path:
            messagebox.showerror("Error", "Please specify output folder.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        self.status.set("Processing...")
        self.update()

        key = hashlib.sha256(password.encode()).digest()[:KEY_LEN]

        try:
            if os.path.isfile(input_path):
                # Single file process
                output_file = output_path
                if os.path.isdir(output_path):
                    # If output is folder, preserve filename
                    filename = os.path.basename(input_path)
                    output_file = os.path.join(output_path, filename)
                if mode == 'encrypt':
                    self.encrypt_file(input_path, output_file, key)
                else:
                    self.decrypt_file(input_path, output_file, key)
            elif os.path.isdir(input_path):
                # Folder process
                self.process_folder(mode, input_path, output_path, key)
            else:
                messagebox.showerror("Error", "Input path is not a valid file or folder.")
                self.status.set("")
                return

            if delete_original:
                if os.path.isfile(input_path):
                    os.remove(input_path)
                else:
                    shutil.rmtree(input_path)
                self.status.set("Original deleted.")
            else:
                self.status.set("Done.")

            messagebox.showinfo("Success", f"{mode.title()}ion complete!")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.set("")

    def encrypt_file(self, input_path, output_path, key):
        with open(input_path, 'rb') as f:
            data = bytearray(f.read())
        for i in range(len(data)):
            data[i] = (data[i] + key[i % len(key)]) % 256
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"Encrypted: {input_path}")

    def decrypt_file(self, input_path, output_path, key):
        with open(input_path, 'rb') as f:
            data = bytearray(f.read())
        for i in range(len(data)):
            data[i] = (data[i] - key[i % len(key)]) % 256
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"Decrypted: {input_path}")

    def process_folder(self, mode, input_dir, output_dir, key):
        for root, dirs, files in os.walk(input_dir):
            # Create dirs in output folder
            for dir in dirs:
                rel_dir = os.path.relpath(os.path.join(root, dir), input_dir)
                os.makedirs(os.path.join(output_dir, rel_dir), exist_ok=True)
            # Process files
            for file in files:
                input_file = os.path.join(root, file)
                rel_file = os.path.relpath(input_file, input_dir)
                output_file = os.path.join(output_dir, rel_file)
                if mode == 'encrypt':
                    self.encrypt_file(input_file, output_file, key)
                else:
                    self.decrypt_file(input_file, output_file, key)

if __name__ == "__main__":
    app = EncrypterApp()
    app.mainloop()
