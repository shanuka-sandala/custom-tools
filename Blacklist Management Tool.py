import tkinter as tk
from tkinter import ttk, messagebox
import requests
import os
import hashlib
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import shutil
import re

# Removed Scroll Bar - 2025/02/12 - refer the other for original

class BlacklistUpdater:

    VERSION = "1.0.1"
    AUTHOR = "Shanuka Jayakodi"
    CONTACT = "shanukaj@the-debugging-diaries.com"
    BLOG = "https://the-debugging-diaries.com"

    def __init__(self, root):
        self.root = root
        self.root.title("Blacklist Management Tool")
        self.root.geometry("850x500")

        try:
            root.iconbitmap('bmt.ico')
        except:
            pass  # Silently fail if icon not found
        
        # Configuration
        self.blacklist_path = r"C:\inetpub\IP_Blacklist\blacklist.txt"
        self.max_entries = 50000
        self.backup_days = 3
        self.undo_stack = []
        self.redo_stack = []

        # Create necessary directories
        self.create_directories()
        
        # GUI Components
        self.create_widgets()
        self.setup_layout()
        self.check_undo_availability()

    def create_directories(self):
        paths = [
            os.path.dirname(self.blacklist_path),
            self.get_log_path("deleted-ips"),
            self.get_log_path("uploaded-ips"),
            self.get_backup_path()
        ]
        for path in paths:
            os.makedirs(path, exist_ok=True)

    def create_widgets(self):
        # URL Input
        self.url_frame = ttk.LabelFrame(self.root, text="Download Settings")
        ttk.Label(self.url_frame, text="File URL:").pack(side=tk.LEFT, padx=5)
        
        # Add placeholder text
        self.url_entry = ttk.Entry(self.url_frame, width=70)
        self.url_entry.insert(0, "https://tmpfiles.org/XXXXXX/processed_ips.txt")
        self.url_entry.config(foreground='black')
        self.url_entry.pack(side=tk.LEFT, padx=5)
        
        # Bind focus events
        self.url_entry.bind('<FocusOut>', self.restore_placeholder)

        # Hash Display
        self.hash_frame = ttk.LabelFrame(self.root, text="File Verification")
        self.hash_var = tk.StringVar()
        ttk.Entry(self.hash_frame, textvariable=self.hash_var, 
                width=70, state='readonly').pack(side=tk.LEFT, padx=5)
        ttk.Button(self.hash_frame, text="Copy Hash", 
                 command=self.copy_hash).pack(side=tk.LEFT, padx=5)
        
        # Controls
        self.control_frame = ttk.Frame(self.root)
        self.btn_update = ttk.Button(self.control_frame, text="Update Blacklist", command=self.update_blacklist)
        self.btn_undo = ttk.Button(self.control_frame, text="Undo", command=self.undo_last_update)
        self.btn_redo = ttk.Button(self.control_frame, text="Redo", command=self.redo_last_update)
        self.btn_deduplicate = ttk.Button(self.control_frame, text="Remove Duplicates", command=self.remove_duplicates)
        self.btn_info = ttk.Button(self.control_frame, text="Info", command=self.show_info)

        # Arrange buttons
        self.btn_update.pack(side=tk.LEFT, padx=2)
        self.btn_undo.pack(side=tk.LEFT, padx=2)
        self.btn_redo.pack(side=tk.LEFT, padx=2)
        self.btn_deduplicate.pack(side=tk.LEFT, padx=2)
        self.btn_info.pack(side=tk.RIGHT, padx=2)

        # Status Display
        self.status_text = tk.Text(self.root, height=15, width=90)

    def restore_placeholder(self, event):
        if not self.url_entry.get():
            self.url_entry.insert(0, "https://tmpfiles.org/XXXXXX/processed_ips.txt")
            self.url_entry.config(foreground='black')

    def setup_layout(self):
        self.url_frame.pack(pady=10, padx=10, fill=tk.X)
        self.hash_frame.pack(pady=5, padx=10, fill=tk.X)
        self.control_frame.pack(pady=10, padx=10)
        self.status_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    def calculate_hash(self, content):
        sha256 = hashlib.sha256()
        sha256.update(content)
        return sha256.hexdigest()

    def copy_hash(self):
        if self.hash_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.hash_var.get())
            messagebox.showinfo("Copied", "Hash copied to clipboard!")

    def get_log_path(self, log_type):
        date_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(r"C:\inetpub\logs", date_str, log_type)

    def get_backup_path(self):
        return os.path.join(r"C:\inetpub\backups")

    def verify_file_hash(self, content, expected_hash):
        sha256 = hashlib.sha256()
        sha256.update(content)
        return sha256.hexdigest() == expected_hash.lower()

    def update_blacklist(self):
        url = self.url_entry.get()
        self.hash_var.set("")  # Reset hash display
        
        if not url:
            messagebox.showwarning("Input Error", "Please provide a file URL!")
            return
            
        try:
            # Handle tmpfiles.org page URLs
            if '/dl/' not in url:
                # Fetch the HTML page to find direct download link
                page_response = requests.get(url)
                page_response.raise_for_status()
                soup = BeautifulSoup(page_response.text, 'html.parser')
                download_link = soup.find('a', {'class': 'download'})['href']
                url = download_link

            # Download actual IP list
            response = requests.get(url)
            response.raise_for_status()
            file_content = response.content

            # Calculate and display hash
            file_hash = self.calculate_hash(file_content)
            self.hash_var.set(file_hash)
                
            # Process IP list
            new_ips = response.text.splitlines()
            
            # Backup current blacklist
            self.create_backup()
            
            # Process existing entries
            existing_entries = self.read_blacklist()
            urls = [entry for entry in existing_entries if not self.is_ip(entry)]
            existing_ips = [entry for entry in existing_entries if self.is_ip(entry)]
            
            # Combine and trim
            updated_ips = existing_ips + new_ips
            overflow = len(updated_ips) + len(urls) - self.max_entries
            deleted_ips = []
            
            if overflow > 0:
                deleted_ips = updated_ips[:overflow]
                updated_ips = updated_ips[overflow:]
                
            # Save deleted IPs
            if deleted_ips:
                self.log_deleted_ips(deleted_ips)
                
            # Save new IPs
            self.log_uploaded_ips(new_ips)
            
            # Write updated blacklist
            with open(self.blacklist_path, 'w') as f:
                f.write('\n'.join(urls + updated_ips))
                
            self.update_status(f"Update successful!\n"
                              f"- Added {len(new_ips)} IPs\n"
                              f"- Deleted {len(deleted_ips)} old IPs\n"
                              f"- File SHA256: {file_hash}")
            self.check_undo_availability()
            
        except Exception as e:
            self.update_status(f"Error: {str(e)}", error=True)

    def is_ip(self, entry):
        return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', entry)

    def read_blacklist(self):
        if os.path.exists(self.blacklist_path):
            with open(self.blacklist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return []

    def log_deleted_ips(self, ips):
        log_file = os.path.join(self.get_log_path("deleted-ips"), "deleted-ips.txt")
        with open(log_file, 'a') as f:
            f.write('\n'.join(ips) + '\n')

    def log_uploaded_ips(self, ips):
        log_file = os.path.join(self.get_log_path("uploaded-ips"), "uploaded-ips.txt")
        with open(log_file, 'w') as f:
            f.write('\n'.join(ips))

    def create_backup(self, action_type="update"):
        backup_dir = self.get_backup_path()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"{action_type}_backup_{timestamp}.txt")
        shutil.copy2(self.blacklist_path, backup_file)
        self.undo_stack.append(backup_file)
        self.redo_stack.clear()  # Clear redo stack on new action
        self.cleanup_old_backups()

    def cleanup_old_backups(self):
        backup_dir = self.get_backup_path()
        cutoff = datetime.now() - timedelta(days=self.backup_days)
        for fname in os.listdir(backup_dir):
            path = os.path.join(backup_dir, fname)
            if os.path.getmtime(path) < cutoff.timestamp():
                os.remove(path)

    def undo_last_update(self):
        if self.undo_stack:
            backup_file = self.undo_stack.pop()
            redo_file = self.create_redo_backup()
            self.redo_stack.append(redo_file)
            shutil.copy2(backup_file, self.blacklist_path)
            os.remove(backup_file)
            self.update_status(f"Undo successful! Restored version from {os.path.basename(backup_file)}")
            self.check_button_availability()

    def redo_last_update(self):
        if self.redo_stack:
            backup_file = self.redo_stack.pop()
            undo_file = self.create_undo_backup()
            self.undo_stack.append(undo_file)
            shutil.copy2(backup_file, self.blacklist_path)
            os.remove(backup_file)
            self.update_status(f"Redo successful! Restored version from {os.path.basename(backup_file)}")
            self.check_button_availability()

    def create_undo_backup(self):
        return self._create_action_backup("undo")

    def create_redo_backup(self):
        return self._create_action_backup("redo")

    def _create_action_backup(self, action_type):
        backup_dir = self.get_backup_path()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"{action_type}_backup_{timestamp}.txt")
        shutil.copy2(self.blacklist_path, backup_file)
        return backup_file

    def remove_duplicates(self):
        try:
            self.create_backup("deduplicate")
            existing_entries = self.read_blacklist()
            
            # Separate URLs and IPs
            urls, ips = [], []
            for entry in existing_entries:
                if self.is_ip(entry):
                    ips.append(entry)
                else:
                    urls.append(entry)
            
            # Remove duplicate IPs while preserving order
            seen = set()
            deduped_ips = []
            for ip in reversed(ips):
                if ip not in seen:
                    seen.add(ip)
                    deduped_ips.insert(0, ip)
            
            removed_count = len(ips) - len(deduped_ips)
            
            # Write updated file
            with open(self.blacklist_path, 'w') as f:
                f.write('\n'.join(urls + deduped_ips))
            
            self.update_status(f"Removed {removed_count} duplicate IPs")
            self.check_button_availability()
            
        except Exception as e:
            self.update_status(f"Deduplication failed: {str(e)}", error=True)

    def show_info(self):
        info_text = (
            f"Version: {self.VERSION}\n"
            f"Author: {self.AUTHOR}\n"
            f"Contact: {self.CONTACT}\n"
            f"Blog: {self.BLOG}"
        )
        messagebox.showinfo("Application Information", info_text)

    def check_button_availability(self):
        self.btn_undo.config(state=tk.NORMAL if self.undo_stack else tk.DISABLED)
        self.btn_redo.config(state=tk.NORMAL if self.redo_stack else tk.DISABLED)
        self.btn_deduplicate.config(state=tk.NORMAL if os.path.exists(self.blacklist_path) else tk.DISABLED)

    def check_undo_availability(self):
        backup_dir = self.get_backup_path()
        backups = [f for f in os.listdir(backup_dir) if f.startswith("blacklist_backup")]
        self.btn_undo.config(state=tk.NORMAL if backups else tk.DISABLED)

    def update_status(self, message, error=False):
        tag = "ERROR" if error else "INFO"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] [{tag}] {message}\n")
        self.status_text.see(tk.END)
        if error:
            messagebox.showerror("Error", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = BlacklistUpdater(root)
    root.mainloop()