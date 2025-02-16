import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
from bs4 import BeautifulSoup
import os
import threading
import hashlib

class FileTransferApp:
    
    def __init__(self, root):
        self.root = root
        self.root.title("File Transfer Tool")
        self.root.geometry("650x450")
        
        # Application metadata
        self.VERSION = "1.0.0"
        self.AUTHOR = "Shanuka Jayakodi"
        self.CONTACT = "shanuka@the-debugging-diaries.com"
        self.BLOG = "https://the-debugging-diaries.com"

        # Hardcoded download location
        self.download_path = os.path.join(os.path.expanduser("~"), "Downloads")
        if not os.path.exists(self.download_path):
            os.makedirs(self.download_path)

        # Upload Frame
        upload_frame = ttk.LabelFrame(root, text="File Upload")
        upload_frame.pack(pady=10, padx=20, fill="x")
        
        # Browse and Info buttons
        button_frame = ttk.Frame(upload_frame)
        button_frame.pack(pady=5)
        
        self.btn_browse = ttk.Button(button_frame, text="Browse File", command=self.browse_file)
        self.btn_browse.pack(side=tk.LEFT, padx=5)
        
        self.btn_info = ttk.Button(button_frame, text="ℹ️ About", command=self.show_info)
        self.btn_info.pack(side=tk.LEFT, padx=5)
        
        self.lbl_file = ttk.Label(upload_frame, text="No file selected")
        self.lbl_file.pack()
        
        # Upload progress bar
        self.upload_progress = ttk.Progressbar(upload_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.upload_progress.pack(pady=5, fill=tk.X, padx=10)
        self.upload_progress.pack_forget()
        
        self.btn_upload = ttk.Button(upload_frame, text="Upload", command=self.start_upload_thread)
        self.btn_upload.pack(pady=5)
        
        # URL and Checksum display
        url_frame = ttk.Frame(upload_frame)
        url_frame.pack(fill="x", pady=5, anchor='center')
        
        self.url_entry = ttk.Entry(url_frame, state="readonly", width=40)
        self.url_entry.pack(side=tk.TOP, padx=5)
        
        self.copy_btn = ttk.Button(url_frame, text="📋", width=3, command=self.copy_url)
        self.copy_btn.pack(side=tk.TOP)
        
        self.upload_checksum_label = ttk.Label(upload_frame, text="SHA-256: ")
        self.upload_checksum_label.pack(pady=5)

        # Download Frame
        download_frame = ttk.LabelFrame(root, text="File Download")
        download_frame.pack(pady=10, padx=20, fill="x")
        
        self.url_entry_download = ttk.Entry(download_frame, width=50)
        self.url_entry_download.pack(pady=5, padx=5)
        
        # Download progress bar
        self.download_progress = ttk.Progressbar(download_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.download_progress.pack(pady=5, fill=tk.X, padx=10)
        self.download_progress.pack_forget()
        
        self.btn_download = ttk.Button(download_frame, text="Download", command=self.start_download_thread)
        self.btn_download.pack(pady=5)
        
        self.download_checksum_label = ttk.Label(download_frame, text="SHA-256: ")
        self.download_checksum_label.pack(pady=5)
        
        self.download_status = ttk.Label(download_frame, text="")
        self.download_status.pack()

    def show_info(self):
        """Display application information in a dialog"""
        info_message = (
            f"Version: {self.VERSION}\n"
            f"Author: {self.AUTHOR}\n"
            f"Contact: {self.CONTACT}\n"
            f"Blog: {self.BLOG}"
        )
        messagebox.showinfo("About File Transfer Tool", info_message)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.lbl_file.config(text=os.path.basename(self.file_path))

    def start_upload_thread(self):
        threading.Thread(target=self.upload_file, daemon=True).start()

    def upload_file(self):
        if not hasattr(self, 'file_path'):
            self.root.after(0, lambda: messagebox.showerror("Error", "Please select a file first!"))
            return
            
        try:
            self.root.after(0, self.upload_progress.pack)
            filesize = os.path.getsize(self.file_path)
            self.root.after(0, self.upload_progress.config, {'maximum': filesize, 'value': 0})

            class ProgressReader:
                def __init__(self, filename, callback):
                    self.filename = filename
                    self.callback = callback
                    self.file = open(filename, 'rb')
                    self.total_read = 0
                    self.sha256 = hashlib.sha256()

                def read(self, size=-1):
                    data = self.file.read(size)
                    if data:
                        self.total_read += len(data)
                        self.sha256.update(data)
                        self.callback(self.total_read)
                    return data

                def __len__(self):
                    return os.path.getsize(self.filename)

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_val, exc_tb):
                    self.file.close()

            def update_progress(value):
                self.root.after(0, self.upload_progress.config, {'value': value})

            with ProgressReader(self.file_path, update_progress) as f:
                response = requests.post('https://tmpfiles.org/api/v1/upload', 
                                      files={'file': (os.path.basename(self.file_path), f)},
                                      timeout=30)
                
                if response.status_code != 200:
                    raise Exception(f"Server returned status {response.status_code}")
                    
                try:
                    response_data = response.json()
                    if 'data' not in response_data or 'url' not in response_data['data']:
                        raise Exception("Invalid server response format")
                    self.upload_url = response_data['data']['url']
                except ValueError:
                    raise Exception("Invalid server response")

                # Update UI with checksum
                file_checksum = f.sha256.hexdigest()
                self.root.after(0, self.upload_checksum_label.config, 
                               {'text': f"SHA-256: {file_checksum}"})
                
                self.root.after(0, self.url_entry.config, {'state': 'normal'})
                self.root.after(0, self.url_entry.delete, 0, tk.END)
                self.root.after(0, self.url_entry.insert, 0, self.upload_url)
                self.root.after(0, self.url_entry.config, {'state': 'readonly'})
                self.root.after(0, lambda: messagebox.showinfo("Success", 
                    f"File uploaded successfully!\nChecksum: {file_checksum}"))
                
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Upload Failed", f"Error: {msg}"))
        finally:
            self.root.after(0, self.upload_progress.pack_forget)

    def start_download_thread(self):
        threading.Thread(target=self.download_file, daemon=True).start()

    def download_file(self):
        url = self.url_entry_download.get().strip()
        if not url:
            self.root.after(0, lambda: messagebox.showerror("Error", "Please enter a URL!"))
            return
            
        try:
            if not url.startswith(('http://', 'https://')):
                raise ValueError("Invalid URL format")

            if '/dl/' not in url:
                page = requests.get(url)
                page.raise_for_status()
                soup = BeautifulSoup(page.text, 'html.parser')
                download_link = soup.find('a', {'class': 'download'})
                if not download_link:
                    raise Exception("Download link not found on page")
                url = download_link['href']

            self.root.after(0, self.download_progress.pack)
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            filename = os.path.basename(url)
            save_path = os.path.join(self.download_path, filename)

            self.root.after(0, self.download_progress.config, {'value': 0})
            if total_size > 0:
                self.root.after(0, self.download_progress.config, {'maximum': total_size})

            sha256 = hashlib.sha256()
            downloaded = 0
            
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024*1024):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        sha256.update(chunk)
                        if total_size > 0:
                            self.root.after(0, self.download_progress.config, {'value': downloaded})
                        self.root.after(0, self.root.update_idletasks)

            # Update download checksum display
            actual_checksum = sha256.hexdigest()
            self.root.after(0, self.download_checksum_label.config,
                          {'text': f"SHA-256: {actual_checksum}"})
            
            self.root.after(0, lambda: messagebox.showinfo("Success", 
                f"File saved to:\n{save_path}\nChecksum: {actual_checksum}"))
            
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Download Failed", f"Error: {msg}"))
        finally:
            self.root.after(0, self.download_progress.pack_forget)

    def copy_url(self):
        if hasattr(self, 'upload_url'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.upload_url)
            self.root.after(0, lambda: messagebox.showinfo("Copied", "URL copied to clipboard!"))

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()