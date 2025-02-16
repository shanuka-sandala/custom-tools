import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import pandas as pd
import ipaddress
import hashlib
import os
import re

class EnhancedFileUploader:

    VERSION = "1.0.0"
    AUTHOR = "Shanuka Jayakodi"
    CONTACT = "shanuka@the-debugging-diaries.com"
    BLOG = "https://the-debugging-diaries.com"

    def __init__(self, root):
        self.root = root
        self.root.title("Malicious IP Processor")
        self.root.geometry("800x500")

        try:
            root.iconbitmap('MIP.ico')
        except:
            pass  # Silently fail if icon not found
        
        # Configuration
        self.temp_file = "processed_ips.txt"
        self.expected_column = "Malicious IP"
        
        # Main UI Components
        self.create_widgets()
        self.setup_layout()

    def create_widgets(self):
        # File Selection
        self.file_path = tk.StringVar()
        self.file_frame = ttk.LabelFrame(self.root, text="File Selection")
        ttk.Label(self.file_frame, text="Excel File:").pack(side=tk.LEFT, padx=5)
        ttk.Entry(self.file_frame, textvariable=self.file_path, width=50).pack(side=tk.LEFT)
        ttk.Button(self.file_frame, text="Browse", command=self.browse_excel).pack(side=tk.LEFT, padx=5)
                
        # Processing Controls
        self.process_frame = ttk.LabelFrame(self.root, text="Processing Controls")
        ttk.Button(self.process_frame, text="Process & Upload", command=self.process_and_upload).pack(side=tk.LEFT, pady=5, padx=5)
        ttk.Button(self.process_frame, text="Info", command=self.show_info).pack(side=tk.LEFT, padx=5)
        
        # Results Display
        self.results_frame = ttk.LabelFrame(self.root, text="Processing Results")
        self.results_text = tk.Text(self.results_frame, height=15, width=95)
        self.results_text.pack(padx=5, pady=5)
        
        # URL Display
        self.url_frame = ttk.LabelFrame(self.root, text="Download URL")
        self.url_var = tk.StringVar()
        ttk.Entry(self.url_frame, textvariable=self.url_var, width=70, state='readonly').pack(padx=5, pady=5)
        ttk.Button(self.url_frame, text="Copy URL", command=self.copy_url).pack(pady=5)

    def show_info(self):
        info_text = (
            f"Version: {self.VERSION}\n"
            f"Author: {self.AUTHOR}\n"
            f"Contact: {self.CONTACT}\n"
            f"Blog: {self.BLOG}"
        )
        messagebox.showinfo("Application Information", info_text)

    def setup_layout(self):
        self.file_frame.pack(pady=10, padx=10, fill=tk.X)
        self.process_frame.pack(pady=10, padx=10, fill=tk.X)
        self.results_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.url_frame.pack(pady=10, padx=10, fill=tk.X)
        
    def browse_excel(self):
        path = filedialog.askopenfilename(
            filetypes=[("Excel Files", "*.xlsx *.xls")]
        )
        if path:
            self.file_path.set(path)
            self.clear_results()
            
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.url_var.set('')
            
    def process_and_upload(self):
        if not self.file_path.get():
            messagebox.showwarning("Warning", "Please select an Excel file first!")
            return
            
        try:
            # Read Excel file
            df = pd.read_excel(self.file_path.get())
            
            # Find IP column
            ip_column = self.find_ip_column(df)
            if not ip_column:
                messagebox.showerror("Error", f"Column '{self.expected_column}' not found in Excel file")
                return
                
            # Process IP addresses
            processed_ips = self.process_ips(df[ip_column])
            
            # Validate results
            result = self.process_ips(df[ip_column])
            
            # Validate results
            if not result['valid_ips']:
                messagebox.showwarning("Warning", "No valid public IP addresses found after processing")
                return
                
            # Create text file
            self.create_text_file(result['valid_ips'])
            
            # Generate hash
            file_hash = self.generate_file_hash()
            
            # Upload file
            self.upload_file()
            
            # Show results
            self.display_results(result, file_hash)
            
        except Exception as e:
            messagebox.showerror("Processing Error", str(e))
            
    def find_ip_column(self, df):
        # Case-insensitive column search
        for col in df.columns:
            if self.expected_column.lower() in col.lower():
                return col
        return None
        
    def process_ips(self, ip_series):
        cleaned_ips = []
        invalid_entries = []
        private_ips = []
        
        for ip in ip_series.dropna().astype(str):
            try:
                original_ip = ip
                clean_ip = ip.replace('[.]', '.').strip()
                
                # Validate IP format
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_ip):
                    invalid_entries.append(original_ip)
                    continue
                    
                # Check for private IPs
                ip_obj = ipaddress.IPv4Address(clean_ip)
                if ip_obj.is_private:
                    private_ips.append(clean_ip)
                    continue
                    
                cleaned_ips.append(str(ip_obj))
                
            except (ValueError, ipaddress.AddressValueError):
                invalid_entries.append(original_ip)
                continue
                
        # Remove duplicates while preserving order
        seen = set()
        unique_ips = []
        for ip in cleaned_ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
                
        return {
            'valid_ips': unique_ips,
            'invalid_entries': list(set(invalid_entries)),  # Deduplicate
            'private_ips': list(set(private_ips))          # Deduplicate
        }
        
    def create_text_file(self, ips):
        # Check count warning
        if len(ips) > 50000:
            messagebox.showwarning("Large Dataset", 
                f"Warning: {len(ips)} IPs detected (over 50,000 limit)")
            
        # Save to text file
        with open(self.temp_file, 'w') as f:
            f.write('\n'.join(ips))
            
    def generate_file_hash(self):
        sha256 = hashlib.sha256()
        with open(self.temp_file, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
        
    def upload_file(self):
        try:
            with open(self.temp_file, 'rb') as f:
                response = requests.post('https://tmpfiles.org/api/v1/upload', files={'file': f})
                result = response.json()
                if result.get('status') == 'success':
                    self.url_var.set(result['data']['url'])
                else:
                    raise ValueError("Upload failed: Invalid server response")
        finally:
            if os.path.exists(self.temp_file):
                os.remove(self.temp_file)
                
    def display_results(self, results, file_hash):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Processing Summary:\n")
        self.results_text.insert(tk.END, f"- Total Valid IPs: {len(results['valid_ips'])}\n")
        self.results_text.insert(tk.END, f"- Invalid Entries Found: {len(results['invalid_entries'])}\n")
        self.results_text.insert(tk.END, f"- Private IPs Filtered: {len(results['private_ips'])}\n")
        self.results_text.insert(tk.END, f"- File SHA-256 Hash: {file_hash}\n")
        
        # Show samples of filtered items
        self.results_text.insert(tk.END, "\n\n=== Invalid Entries (Sample) ===\n")
        sample_invalid = results['invalid_entries'][:5] if results['invalid_entries'] else ["None found"]
        self.results_text.insert(tk.END, '\n'.join(sample_invalid))
        
        self.results_text.insert(tk.END, "\n\n=== Private IPs Filtered (Sample) ===\n")
        sample_private = results['private_ips'][:5] if results['private_ips'] else ["None found"]
        self.results_text.insert(tk.END, '\n'.join(sample_private))
        
        self.results_text.insert(tk.END, "\n\n=== Valid Public IPs (First 10) ===\n")
        self.results_text.insert(tk.END, '\n'.join(results['valid_ips'][:10]))
        
    def copy_url(self):
        if self.url_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.url_var.get())
            messagebox.showinfo("Copied", "URL copied to clipboard!")

if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedFileUploader(root)
    root.mainloop()