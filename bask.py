import atexit
import datetime
import time
import time as tm
from pathlib import Path
import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import Label, filedialog
from tkinter import simpledialog
import tkinter.ttk as ttk
from tkinter.constants import *
import os.path
from tkinter import messagebox
import OpenSSL
import glob
import re
import cryptography
from OpenSSL import crypto
import psutil
from datetime import datetime
import json
import requests

_script = sys.argv[0]
_location = os.path.dirname(_script)



_bgcolor = '#d9d9d9'  # X11 color: 'gray85'
_fgcolor = '#000000'  # X11 color: 'black'
_compcolor = 'gray40' # X11 color: #666666
_ana1color = '#c3c3c3' # Closest X11 color: 'gray76'
_ana2color = 'beige' # X11 color: #f5f5dc
_tabfg1 = 'black' 
_tabfg2 = 'black' 
_tabbg1 = 'grey75' 
_tabbg2 = 'grey89' 
_bgmode = 'light' 
font9 = "-family {Times New Roman} -size 12"



def change_cert_friendly_name(thumbprint, new_name):
    try:
        script = f'''
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'My','LocalMachine'
        $store.Open('ReadWrite')
        $cert = $store.Certificates | Where-Object {{ $_.Thumbprint -eq "{thumbprint}" }}
        if($cert) {{
            $cert.FriendlyName = "{new_name}"
        }} else {{
            throw "Certificate not found"
        }}
        $store.Close()
        '''
        subprocess.run(['powershell', '-Command', script], check=True)
        messagebox.showinfo("Success", f"Changed the friendly name of the certificate with thumbprint {thumbprint} to {new_name}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"An error occurred while trying to change the friendly name of the certificate: {e}")

def change_friendly_button_click(tree):
    selected_item = tree.selection()
    if selected_item:  # If there is a selection
        item = tree.item(selected_item[0])  # Get the first selected item
        key_thumbprint = item['values'][1]  # Thumbprint is in the second column
        new_name = simpledialog.askstring("Change Friendly Name", "Enter new friendly name:")  # Get new friendly name from the user
        if new_name:  # If user entered a new friendly name
            change_cert_friendly_name(key_thumbprint, new_name)  # Change the friendly name
        else:
            messagebox.showerror("Error", "No friendly name entered")  # Show error if no friendly name was entered
    else:
        messagebox.showerror("Error", "No item selected")  # Show error if no item was selected

def copy_thumbprint(tree):
    selected_item = tree.selection()
    if selected_item:  # If there is a selection
        item = tree.item(selected_item[0])  # Get the first selected item
        thumbprint = item['values'][1]  # Thumbprint is in the second column
        root.clipboard_clear()
        root.clipboard_append(thumbprint)
        tk.messagebox.showinfo("Success", f"Thumbprint copied: {thumbprint}")
    else:
        tk.messagebox.showerror("Error", "No item selected")

def on_cert_details_button_click(tree):
    selected_item = tree.selection()
    if selected_item:  # If there is a selection
        item = tree.item(selected_item[0])  # Get the first selected item
        details_thumbprint = item['values'][1]  # Thumbprint is in the second column
        open_certificate_details(details_thumbprint)
    else:
        messagebox.showerror("Error", "No item selected")

def open_certificate_details(details_thumbprint):
    system_root = os.environ.get('SystemRoot', 'C:\\Windows')
    powershell_path = os.path.join(system_root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    try:
        # Export the certificate to a temporary file in binary format
        temp_cert_file = os.path.join(os.path.expanduser("~"), "Documents", "temp.cer")
        cert_path = f"Cert:\\LocalMachine\\My\\{details_thumbprint}"

        print(f"Temp Cert File: {temp_cert_file}")
        print(f"Cert Path: {cert_path}")
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        subprocess.run([powershell_path, "-Command", f"Export-Certificate -Cert {cert_path} -FilePath {temp_cert_file}"],
                        startupinfo=startupinfo)

        print("Certificate exported successfully.")

        # Open the certificate in the default viewer
        subprocess.Popen(["start", "", temp_cert_file], shell=True, startupinfo=startupinfo)

        print("Certificate viewer opened.")

        # Register a function to delete the temporary file on exit
        def delete_temp_file():
            os.unlink(temp_cert_file)

        atexit.register(delete_temp_file)

    except Exception as e:
        messagebox.showerror("Error", f"Error occurred while opening certificate details: {e}")

        # Print the exception traceback for further debugging
        import traceback
        traceback.print_exc()

def on_key_check_button_click(tree):
    selected_item = tree.selection()
    if selected_item:  # If there is a selection
        item = tree.item(selected_item[0])  # Get the first selected item
        key_thumbprint = item['values'][1]  # Thumbprint is in the second column
        check_key(key_thumbprint)
    else:
        messagebox.showerror("Error", "No item selected")

def check_key(key_thumbprint):
    system_root = os.environ.get('SystemRoot', 'C:\\Windows')
    powershell_path = os.path.join(system_root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        # Test the private key
        powershell_cmd = f"(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {{$_.Thumbprint -eq '{key_thumbprint}'}}).HasPrivateKey"
        process = subprocess.run([powershell_path, "-Command", powershell_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        output = process.stdout.decode("utf-8")
        error = process.stderr.decode("utf-8")
        if "True" in output:
            messagebox.showinfo("Success", "Private key found for the selected certificate")
        elif "False" in output:
            messagebox.showerror("Error", "Private key not found for the selected certificate")
        else:
            messagebox.showwarning("Warning", "Private key status is unknown")

        # Check for certificate revocation
        powershell_cmd = f"(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {{$_.Thumbprint -eq '{key_thumbprint}'}}).Verify()"
        process = subprocess.run([powershell_path, "-Command", powershell_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        output = process.stdout.decode("utf-8")
        error = process.stderr.decode("utf-8")
        if "True" in output:
            messagebox.showinfo("Success", "Certificate is valid and not revoked")
        elif "False" in output:
            messagebox.showwarning("Warning", "Certificate is revoked")
        else:
            messagebox.showwarning("Warning", "Revocation check status is unknown")

    except Exception as e:
        messagebox.showerror("Error", f"Error occurred during key check: {e}")

def on_export_cert_button_click(tree):
    selected_item = tree.selection()[0]
    thumbprint = tree.item(selected_item)['values'][1] 
    if thumbprint:
        export_certificate(thumbprint)
    else:
        messagebox.showerror("Error", "No item selected")

def export_certificate(thumbprint): 
    export_window = tk.Toplevel(root)
    export_window.title("Export Certificate")
    export_window.resizable(False, False)
    export_window.geometry("265x200")
    script_dir = os.path.dirname(os.path.realpath(__file__))
    icon_ico = os.path.join(script_dir, "BASK.ico")
    export_window.iconbitmap(icon_ico)

    selected_format = tk.StringVar()
    pfx_radio = ttk.Radiobutton(export_window, text="PFX File", variable=selected_format, value="pfx")
    pfx_radio.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

    key_radio = ttk.Radiobutton(export_window, text="Key File (Apache)", variable=selected_format, value="key")
    key_radio.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    
    def export_button_click():
        export_format = selected_format.get()
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        certutil_path = os.path.join(system_root, 'System32', 'certutil.exe')

        if export_format == "pfx":
        # Export as PFX file
            pfx_file_path = filedialog.asksaveasfilename(defaultextension=".pfx", filetypes=[("PFX Files", "*.pfx")])
            if not pfx_file_path:
                return

            pfx_password = simpledialog.askstring("PFX Password", "Enter a password for the PFX file:", show="*")
            if not pfx_password:
                return
            command = f'{certutil_path} -exportPFX -p "{pfx_password}" -privatekey "{thumbprint}" "{pfx_file_path}"'
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to export certificate: {result.stderr}")
                return
        elif export_format == "key":
    # Export as Key File (Apache)
            key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
            if not key_file_path:
                return

            temp_pfx_file_path = os.path.join(os.path.dirname(key_file_path), "temp.pfx")
            temp_pfx_password="1234"

    # Export the private key in PFX format to a temporary file
    
            command = f'{certutil_path} -exportPFX -p "{temp_pfx_password}" -privatekey "{thumbprint}" "{temp_pfx_file_path}"'
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode != 0:
                messagebox.showerror("Error", f"Failed to export PFX file: {result.stderr}")
                return

    # Extract the private key from the temporary PFX file
            with open(temp_pfx_file_path, "rb") as pfx_file:
                pfx_data = pfx_file.read()
            pfx = OpenSSL.crypto.load_pkcs12(pfx_data, temp_pfx_password.encode())
            key = pfx.get_privatekey()

    # Save the private key to the specified file
            with open(key_file_path, "wb") as key_file:
                key_file.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
                
    # Delete the temporary PFX file
            os.remove(temp_pfx_file_path)

            messagebox.showinfo("Success", "Private key exported successfully.")
            export_window.destroy()

    export_button = ttk.Button(export_window, text="Export", command=export_button_click)
    export_button.grid(row=2, column=0, pady=10, padx=5)

    export_window.mainloop()

def import_certificate():
        """Import the certificate into the Windows certificate store."""
        try:
            # Select the certificate file to import
            certificate_file = filedialog.askopenfilename(initialdir=".", title="Select Certificate File", filetypes=[("Certificate Files", "*.cer, *.crt")])
            if certificate_file:
                # Import the certificate using Certreq.exe
                import_cmd = ["certreq", "-accept", certificate_file]
                subprocess.run(import_cmd, capture_output=True, check=True)
				# Display a message box indicating success
                messagebox.showinfo("Certificate Imported", "The certificate was successfully imported.")
        except Exception as e:
            # Display a message box indicating the error
            messagebox.showerror("Error", f"An error occurred while importing the certificate:\n{e}")

def open_certlm():
    system_root = os.environ.get('SystemRoot', 'C:\\Windows')
    certlm_path = os.path.join(system_root, 'System32', 'certlm.msc')
    #command = f'mmc.exe certlm.msc'
    subprocess.Popen(certlm_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def open_iis():
    try:
        subprocess.run('C:\\Windows\\System32\\inetsrv\\InetMgr.exe')
    except Exception as e:
        messagebox.showerror("Error", f"IIS not installed:\n{e}")

def create_context_menu(widget):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
    widget.bind("<Button-3>", lambda event: menu.post(event.x_root, event.y_root))





class Toplevel1:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        top.title("B.A.S.K.")
        
        window_width = 700
        window_height = 420

        screen_width = top.winfo_screenwidth()
        screen_height = top.winfo_screenheight()

        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(screen_width, screen_height)
        top.resizable(False, False)

        self.top = top
        self.style=ttk.Style()
        
        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.realpath(__file__))

        # Construct the path to the azure.tcl file
        azure_tcl_path = os.path.join(script_dir, "azure", "azure.tcl")

        # Call the source procedure with the path to the azure.tcl file
        top.tk.call("source", azure_tcl_path)
        top.call("set_theme", "light")
        top.update_idletasks()
        self.style.configure("Treeview", font=('Times New Roman', '10', 'bold'), rowheight=35)
        
        self.tree = ttk.Treeview(top, style="Custom.Treeview")

        self.tree = ttk.Treeview(top,
        columns=(
            "Issued to",
            "Thumbprint",
            "Serial Number",
            "Expires",
            "Friendly Name",
        ),
        show="headings",
    )

        for col in (
            "Issued to",
            "Thumbprint",
            "Serial Number",
            "Expires",
            "Friendly Name",
        ):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=175, minwidth=175)  # Set a minimum width for each column

    # Place the Treeview on the top window
        self.tree.place(relx=0.019, rely=0.291, relheight=0.480, relwidth=0.700)

    # Create and place the scrollbars
        self.xscrollbar = tk.Scrollbar(top, orient='horizontal', command=self.tree.xview)
        self.xscrollbar.place(relx=0.019, rely=0.786, relwidth=0.694)
        self.yscrollbar = tk.Scrollbar(top, orient='vertical', command=self.tree.yview)
        self.yscrollbar.place(relx=0.726, rely=0.291, relheight=0.420)

# Link the scrollbars to the Treeview
        self.tree.configure(xscrollcommand=self.xscrollbar.set, yscrollcommand=self.yscrollbar.set)
        
        self.populate_tree()

    def refresh_tree(self):
        # Clear the existing treeview
        self.tree.delete(*self.tree.get_children())
        
        # Populate the treeview with new data
        self.populate_tree()

    def run_command(self):
        system_root = os.environ.get('SystemRoot', 'C:\\Windows')
        powershell_path = os.path.join(system_root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
        command = [
            powershell_path,
            "Get-ChildItem -Path Cert:/LocalMachine/My | Format-List Subject, Thumbprint, SerialNumber, NotAfter, FriendlyName",
        ]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        output, error = process.communicate()

        if error:
            print(f"Error: {error}")
        else:
            cert_data = output.decode("utf-8").split("\n")
            cert_data = [line.strip() for line in cert_data if line.strip()]
            return cert_data

    def populate_tree(self):
        cert_data = self.run_command()
        if cert_data:
            cert_dict = {}
            for line in cert_data:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                cert_dict[key] = value

                if key == "FriendlyName":
                    self.tree.insert("", "end", values=(cert_dict.get("Subject"), cert_dict.get("Thumbprint"), cert_dict.get("SerialNumber"),
                                                        cert_dict.get("NotAfter"), cert_dict.get("FriendlyName")))
                    cert_dict.clear()


        self.title_label = ttk.Label(self.top)
        self.title_label.place(relx=0.130, rely=0.028, height=51, width=501)
        self.title_label.configure(font="-family {Times New Roman} -size 36 -weight bold")
        self.title_label.configure(relief="flat")
        self.title_label.configure(anchor='w')
        self.title_label.configure(justify='left')
        self.title_label.configure(text='''Bask's Assisted SSL Kit''')
        self.title_label.configure(compound='left')

        self.list_certs_button = ttk.Button(self.top)
        self.list_certs_button.place(relx=0.765, rely=0.300, height=29
                , width=126)
        self.list_certs_button.configure(takefocus="")
        self.list_certs_button.configure(text='''List Certificates''')
        self.list_certs_button.configure(command=lambda: self.refresh_tree())
        self.list_certs_button.configure(compound='left')

        self.cert_details_button = ttk.Button(self.top)
        self.cert_details_button.place(relx=0.765, rely=0.415, height=29
                , width=126)
        self.cert_details_button.configure(takefocus="")
        self.cert_details_button.configure(text='''Certificate Details''')
        self.cert_details_button.configure(command=lambda: on_cert_details_button_click(self.tree))
        self.cert_details_button.configure(compound='left')

        self.check_key_button = ttk.Button(self.top)
        self.check_key_button.place(relx=0.765, rely=0.530, height=29, width=126)
        self.check_key_button.configure(takefocus="")
        self.check_key_button.configure(text='''Check Key''')
        self.check_key_button.configure(command=lambda: on_key_check_button_click(self.tree))
        self.check_key_button.configure(compound='left')

        self.export_cert_button = ttk.Button(self.top)
        self.export_cert_button.place(relx=0.545, rely=0.850, height=29
                , width=126)
        self.export_cert_button.configure(takefocus="")
        self.export_cert_button.configure(text='''Export Certificate''')
        self.export_cert_button.configure(command=lambda: on_export_cert_button_click(self.tree))
        self.export_cert_button.configure(compound='left')

        self.create_csr_button = ttk.Button(self.top)
        self.create_csr_button.place(relx=0.021, rely=0.850, height=29
                , width=126)
        self.create_csr_button.configure(takefocus="")
        self.create_csr_button.configure(text='''Create CSR''')
        self.create_csr_button.configure(command=open_csr_window)
        self.create_csr_button.configure(compound='left')

        self.import_cert_button = ttk.Button(self.top)
        self.import_cert_button.place(relx=0.290, rely=0.850, height=29
                , width=126)
        self.import_cert_button.configure(takefocus="")
        self.import_cert_button.configure(text='''Import Certificate''')
        self.import_cert_button.configure(command=lambda: import_certificate())
        self.import_cert_button.configure(compound='left')

        self.copy_thumbprint_button = ttk.Button(self.top)
        self.copy_thumbprint_button.place(relx=0.765, rely=0.645, height=29
                , width=126)
        self.copy_thumbprint_button.configure(takefocus="")
        self.copy_thumbprint_button.configure(text='''Copy Thumbprint''')
        self.copy_thumbprint_button.configure(command=lambda: copy_thumbprint(self.tree))
        self.copy_thumbprint_button.configure(compound='left')
        

        self.cert_list_label = ttk.Label(self.top)
        self.cert_list_label.place(relx=0.275, rely=0.200, height=23, width=190)
        self.cert_list_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.cert_list_label.configure(relief="flat")
        self.cert_list_label.configure(anchor='w')
        self.cert_list_label.configure(justify='left')
        self.cert_list_label.configure(text='''MMC Certificate List''')
        self.cert_list_label.configure(compound='left')

        self.menubar = tk.Menu(self.top, font="-family {Times New Roman} -size 12"
            ,bg=_bgcolor, fg=_fgcolor)
        self.top.configure(menu = self.menubar)

        self.sub_menu = tk.Menu(self.menubar, activebackground='beige'
            ,activeborderwidth=1, activeforeground='black'
            ,borderwidth=1, disabledforeground='#a3a3a3'
            ,font="-family {Times New Roman} -size 12", foreground='#000000'
            ,tearoff=0)
        self.menubar.add_cascade(compound='left', label='Theme'
            ,menu=self.sub_menu, )
        self.sub_menu.add_command(compound='left',label='Switch Theme', command=lambda: self.switch_theme())
        self.sub_menu1 = tk.Menu(self.menubar, activebackground='beige'
            ,activeborderwidth=1, activeforeground='black'
            ,background='#d9d9d9', borderwidth=1, disabledforeground='#a3a3a3'
            ,font="-family {Times New Roman} -size 12", foreground='#000000'
            ,tearoff=0)
        self.menubar.add_cascade(compound='left', label='Other SSL Tools'
            ,menu=self.sub_menu1, )
        self.sub_menu1.add_command(compound='left'
            ,label='Exchange Shell Command', command=lambda: open_exchange_shell())
        self.sub_menu1.add_command(compound='left',label='Open MMC', command=lambda: open_certlm())
        self.sub_menu1.add_command(compound='left',label='Open IIS', command=lambda: open_iis())
        self.sub_menu1.add_command(compound='left',label='Apache', command=lambda: open_apache_window())
        self.sub_menu1.add_command(compound='left',label='Nginx', command=lambda: open_nginx_window())
       
        self.sub_menu2 = tk.Menu(self.sub_menu1, activebackground='beige'
            ,activeborderwidth=1, activeforeground='black'
            ,background='#d9d9d9', borderwidth=1, disabledforeground='#a3a3a3'
            ,font="-family {Times New Roman} -size 12", foreground='#000000'
            ,tearoff=0)
        self.sub_menu1.add_cascade(compound='left'
            ,label='OpenSSL Command Generators', menu=self.sub_menu2, )
        self.sub_menu2.add_command(compound='left'
            ,label='Standard or Wildcard CSR', command=lambda: open_StandWildToplevel())
        self.sub_menu2.add_command(compound='left', label='UCC Certificate CSR', command=lambda: open_ucc())
 
        self.sub_menu2.add_command(compound='left'
            ,label='CSR from Existing Private Key', command=lambda:open_CSRExistingKey())
        self.sub_menu2.add_command(compound='left',label='Create PFX', command=lambda: open_CreatePFX())
        self.sub_menu2.add_command(compound='left'
            ,label='Extract Key File from PFX', command=lambda: open_ExtractPrivateKey())
        self.sub_menu2.add_command(compound='left'
            ,label='Extract Certificate from PFX', command=lambda : open_ExtractCertificate())
        self.sub_menu2.add_command(compound='left'
            ,label='Remove Password from Key File', command=lambda: open_RemoveKeyPass())
        self.sub_menu2.add_command(compound='left'
            ,label='Convert Private Key to RSA Private Key', command=lambda: open_ConvertKeyFile())
        
        self.menubar.add_command(compound='left',label='Change Friendly Name', command=lambda: change_friendly_button_click(self.tree))

    def switch_theme(self):
    # Declare CURRENT_THEME as global at the beginning of the function
        global CURRENT_THEME
    # Check the current theme and switch to the other theme
        if self.top.tk.call("ttk::style", "theme", "use") == "azure-dark":
            self.top.tk.call("set_theme", "light")
            self.style.configure('TButton', font=('Times New Roman', 10, 'bold'))
            self.style.configure("Treeview", font=('Times New Roman', '12', 'bold'), rowheight=35)
            CURRENT_THEME = "light"  
        else:
            self.top.tk.call("set_theme", "dark")
            self.style.configure('TButton', font=('Times New Roman', 10, 'bold'))
            self.style.configure("Treeview", font=('Times New Roman', '12', 'bold'), rowheight=35)
            CURRENT_THEME = "dark"

    

def open_exchange_shell():
    # Creates a toplevel widget.
    global _top02, _w02
    _top02 = tk.Toplevel(root)
    _w02 = ExchangeShellToplevel(_top02)

class ExchangeShellToplevel:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        main_window = top.master
        window_width = 328
        window_height = 271

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.resizable(False, False)
        top.title("Exchange Management Shell")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)

        self.top = top
        self.root = root
        
        self.menubar = tk.Menu(top, font="-family {Times New Roman} -size 12"
                ,bg=_bgcolor, fg=_fgcolor)
        top.configure(menu = self.menubar)

        
        self.thumbprint_label = ttk.Label(self.top)
        self.thumbprint_label.place(relx=0.03, rely=0.111, height=30, width=111)
        self.thumbprint_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.thumbprint_label.configure(relief="flat")
        self.thumbprint_label.configure(anchor='w')
        self.thumbprint_label.configure(justify='left')
        self.thumbprint_label.configure(text='''Thumbprint:''')
        self.thumbprint_label.configure(compound='left')
        self.tp_entry = ttk.Entry(self.top)
        create_context_menu(self.tp_entry)
        self.tp_entry.place(relx=0.366, rely=0.133, relheight=0.095
                , relwidth=0.598)
        self.tp_entry.configure(takefocus="")
        self.tp_entry.configure(cursor="ibeam")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.341, rely=0.351, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=self.display)
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.345, rely=0.834, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=self.copy_result)
        self.copy_button.configure(compound='left')
        self.result = ScrolledListBox(self.top)
        self.result.place(relx=0.03, rely=0.517, relheight=0.273
                , relwidth=0.936)
        
        self.result.configure(cursor="xterm")
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        

    def display(self):
        message = f"Enable-ExchangeCertificate -Thumbprint '{self.tp_entry.get()}' -Services POP,IMAP,IIS,SMTP"
        self.result.delete(0, tk.END)
        self.result.insert(tk.END, message)
        
    def copy_result(self):
        self.root.clipboard_clear()
        contents = "\n".join(self.result.get(0, tk.END))
        self.root.clipboard_append(contents)

    
def open_nginx_window():
    # Creates a toplevel widget.
    global _top03, _w03
    _top03 = tk.Toplevel(root)
    _w03 = NginxToplevel(_top03,)
    
    _w03.find_info()
class NginxToplevel:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        
        main_window = top.master  # Assuming top is a child window of the main window

        window_width = 608
        window_height = 599

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("B.A.S.K.")
        
        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        
        self.title = ttk.Label(self.top)
        self.title.place(relx=0.099, rely=0.0, height=75, width=439)
        self.title.configure(font="-family {Times New Roman} -size 36 -weight bold")
        self.title.configure(relief="flat")
        self.title.configure(anchor='w')
        self.title.configure(justify='left')
        self.title.configure(text='''Nginx SSL Installer''')
        self.title.configure(compound='left')
        self.common_name_label = ttk.Label(self.top)
        self.common_name_label.place(relx=0.026, rely=0.134, height=30
                , width=141)
        self.common_name_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.common_name_label.configure(relief="flat")
        self.common_name_label.configure(anchor='w')
        self.common_name_label.configure(justify='left')
        self.common_name_label.configure(text='''Common Name:''')
        self.common_name_label.configure(compound='left')
        self.org_label = ttk.Label(self.top)
        self.org_label.place(relx=0.058, rely=0.195, height=30, width=118)
        
        self.org_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.org_label.configure(relief="flat")
        self.org_label.configure(anchor='w')
        self.org_label.configure(justify='left')
        self.org_label.configure(text='''Organization:''')
        self.org_label.configure(compound='left')
        self.dept_label = ttk.Label(self.top)
        self.dept_label.place(relx=0.077, rely=0.257, height=28, width=109)
        
        self.dept_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.dept_label.configure(relief="flat")
        self.dept_label.configure(anchor='w')
        self.dept_label.configure(justify='left')
        self.dept_label.configure(text='''Department:''')
        self.dept_label.configure(compound='left')
        self.city_label = ttk.Label(self.top)
        self.city_label.place(relx=0.179, rely=0.314, height=29, width=47)
        self.city_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.city_label.configure(relief="flat")
        self.city_label.configure(anchor='w')
        self.city_label.configure(justify='left')
        self.city_label.configure(text='''City:''')
        self.city_label.configure(compound='left')
        self.state_label = ttk.Label(self.top)
        self.state_label.place(relx=0.168, rely=0.377, height=30, width=57)
        self.state_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.state_label.configure(relief="flat")
        self.state_label.configure(anchor='w')
        self.state_label.configure(justify='left')
        self.state_label.configure(text='''State:''')
        self.state_label.configure(compound='left')
        self.country_label = ttk.Label(self.top)
        self.country_label.place(relx=0.128, rely=0.447, height=29, width=81)
        self.country_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.country_label.configure(relief="flat")
        self.country_label.configure(anchor='w')
        self.country_label.configure(justify='left')
        self.country_label.configure(text='''Country:''')
        self.country_label.configure(compound='left')
        self.sans_label = ttk.Label(self.top)
        self.sans_label.place(relx=0.164, rely=0.541, height=30, width=59)
        self.sans_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.sans_label.configure(relief="flat")
        self.sans_label.configure(anchor='w')
        self.sans_label.configure(justify='left')
        self.sans_label.configure(text='''SANs:''')
        self.sans_label.configure(compound='left')
        self.cert_path_label = ttk.Label(self.top)
        self.cert_path_label.place(relx=0.028, rely=0.634, height=29, width=143)
        self.cert_path_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.cert_path_label.configure(relief="flat")
        self.cert_path_label.configure(anchor='w')
        self.cert_path_label.configure(justify='left')
        self.cert_path_label.configure(text='''Certificate Path:''')
        self.cert_path_label.configure(compound='left')
        self.key_path_label = ttk.Label(self.top)
        self.key_path_label.place(relx=0.016, rely=0.701, height=29, width=151)
        self.key_path_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.key_path_label.configure(relief="flat")
        self.key_path_label.configure(anchor='w')
        self.key_path_label.configure(justify='left')
        self.key_path_label.configure(text='''Private Key Path:''')
        self.key_path_label.configure(compound='left')
        self.messages = ScrolledText(self.top)
        self.messages.place(relx=0.016, rely=0.768, relheight=0.195
                , relwidth=0.952)
        self.messages.configure(cursor="xterm")
        self.messages.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.messages.configure(foreground="black")
        self.common_name_input = ttk.Entry(self.top)
        create_context_menu(self.common_name_input)
        self.common_name_input.place(relx=0.278, rely=0.139, relheight=0.045
                , relwidth=0.339)
        self.common_name_input.configure(takefocus="")
        
        self.common_name_input_tooltip = \
        ToolTip(self.common_name_input, '''Example: bask.com''')

        self.org_input = ttk.Entry(self.top)
        create_context_menu(self.org_input)
        self.org_input.place(relx=0.28, rely=0.2, relheight=0.045
                , relwidth=0.339)
        self.org_input.configure(takefocus="")
        
        self.org_input_tooltip = \
        ToolTip(self.org_input, '''Example: Bask''')

        self.dept_input = ttk.Entry(self.top)
        create_context_menu(self.dept_input)
        self.dept_input.place(relx=0.28, rely=0.26, relheight=0.045
                , relwidth=0.339)
        self.dept_input.configure(takefocus="")
        
        self.dept_input_tooltip = \
        ToolTip(self.dept_input, '''Example: IT''')

        self.city_input = ttk.Entry(self.top)
        create_context_menu(self.city_input)
        self.city_input.place(relx=0.28, rely=0.317, relheight=0.045
                , relwidth=0.339)
        self.city_input.configure(takefocus="")
        
        self.city_input_tooltip = \
        ToolTip(self.city_input, '''Example: Dallas''')

        self.state_input = ttk.Entry(self.top)
        create_context_menu(self.state_input)
        self.state_input.place(relx=0.28, rely=0.384, relheight=0.045
                , relwidth=0.339)
        self.state_input.configure(takefocus="")
        self.state_input.configure(cursor="ibeam")
        self.state_input_tooltip = \
        ToolTip(self.state_input, '''Example: Texas''')

        self.country_input = ttk.Entry(self.top)
        create_context_menu(self.country_input)
        self.country_input.place(relx=0.28, rely=0.451, relheight=0.045
                , relwidth=0.339)
        self.country_input.configure(takefocus="")
        self.country_input.configure(cursor="ibeam")
        self.country_input_tooltip = \
        ToolTip(self.country_input, '''2 Letters, Example: US''')

        self.sans_input = ScrolledText(self.top)
        create_context_menu(self.sans_input)
        self.sans_input.place(relx=0.281, rely=0.518, relheight=0.102
                , relwidth=0.339)
        self.sans_input.configure(font="-family {Times New Roman} -size 12")
        self.sans_input.configure(insertbackground="black")
        self.sans_input.configure(insertborderwidth="3")
        
        self.sans_input.configure(wrap="none")
        self.cert_path_input = ttk.Entry(self.top)
        create_context_menu(self.cert_path_input)
        self.cert_path_input.place(relx=0.28, rely=0.634, relheight=0.045
                , relwidth=0.339)
        self.cert_path_input.configure(takefocus="")
        self.cert_path_input.configure(cursor="ibeam")
        self.key_path_input = ttk.Entry(self.top)
        create_context_menu(self.key_path_input)
        self.key_path_input.place(relx=0.28, rely=0.701, relheight=0.045
                , relwidth=0.339)
        self.key_path_input.configure(takefocus="")
        
        self.create_csr_button_1 = ttk.Button(self.top)
        self.create_csr_button_1.place(relx=0.691, rely=0.2, height=29
                , width=124)
        self.create_csr_button_1.configure(takefocus="")
        self.create_csr_button_1.configure(text='''Create CSR''')
        self.create_csr_button_1.configure(command=self.create_csr)
        self.create_csr_button_1.configure(compound='left')
        self.import_certficate_button = ttk.Button(self.top)
        self.import_certficate_button.place(relx=0.691, rely=0.317, height=29
                , width=124)
        self.import_certficate_button.configure(takefocus="")
        self.import_certficate_button.configure(text='''Import Certificate''')
        self.import_certficate_button.configure(command=lambda: self.import_certificate())
        self.import_certficate_button.configure(compound='left')
        self.restart_nginx_button = ttk.Button(self.top)
        self.restart_nginx_button.place(relx=0.691, rely=0.451, height=29
                , width=124)
        self.restart_nginx_button.configure(takefocus="")
        self.restart_nginx_button.configure(text='''Restart Nginx''')
        self.restart_nginx_button.configure(command=lambda: self.restart_nginx())
        self.restart_nginx_button.configure(compound='left')
        self.create_pfx_button = ttk.Button(self.top)
        self.create_pfx_button.place(relx=0.691, rely=0.584, height=29
                , width=124)
        self.create_pfx_button.configure(takefocus="")
        self.create_pfx_button.configure(text='''Create PFX''')
        self.create_pfx_button.configure(command=lambda: self.open_pfx_window())
        self.create_pfx_button.configure()
        self.create_pfx_button.configure(compound='left')

    def find_info(self):
        nginx_executable = None
        nginx_conf_path = None
        ssl_cert_path = ""
        ssl_key_path = ""
    
        # Search for nginx executable
        search_dirs = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), "C:\\"]

        for search_dir in search_dirs:
            if not search_dir:
                continue
            for nginx_folder in glob.glob(os.path.join(search_dir, "nginx*")) + glob.glob(os.path.join(search_dir, "Nginx*")):
                exe_path = os.path.join(nginx_folder, "nginx.exe")
                if os.path.exists(exe_path):
                    nginx_executable = exe_path
                    break
            if nginx_executable:
                break

        if not nginx_executable:
            messagebox.showerror("Warning", "Nginx not installed, some features may not work.")
            return

        # Find nginx.conf or ssl.conf file
        conf_folder = os.path.join(os.path.dirname(nginx_executable), "conf")
        for conf_file_name in ["nginx.conf", "ssl.conf"]:
            conf_path = os.path.join(conf_folder, conf_file_name)
            if os.path.exists(conf_path):
                nginx_conf_path = conf_path
                break

        if not nginx_conf_path:
            messagebox.showerror("Error", "Nginx configuration file not found.")
            return

        # Extract ssl_certificate and ssl_certificate_key
        with open(nginx_conf_path, "r") as conf_file:
            conf_data = conf_file.read()

        ssl_cert_match = re.search(r"ssl_certificate\s+(.*?);", conf_data)
        ssl_key_match = re.search(r"ssl_certificate_key\s+(.*?);", conf_data)

        if ssl_cert_match:
            ssl_cert_path = ssl_cert_match.group(1)
        if ssl_key_match:
            ssl_key_path = ssl_key_match.group(1)

        self.nginx_path = nginx_executable

        self.messages.insert('end', f"Found Nginx executable: {nginx_executable}\n")

        # Update cert_path_input and key_path_input
        self.cert_path_input.delete(0, 'end')
        self.cert_path_input.insert(0, ssl_cert_path)
        self.key_path_input.delete(0, 'end')
        self.key_path_input.insert(0, ssl_key_path)
    
    def restart_nginx(self):
        nginx_executable = self.nginx_path
        self.messages.insert('end',f"Nginx path: {nginx_executable}\n")
        nginx_running = False
        nginx_pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.name() == 'nginx.exe':
                nginx_running = True
                nginx_pids.append(proc.info['pid'])

        # Stop nginx if it's already running
        if nginx_running:
            for pid in nginx_pids:
                try:
                    self.messages.insert('end',f"Stopping Nginx process (PID {pid})...\n")
                    subprocess.run(['taskkill', '/F', '/PID', str(pid)], check=True, capture_output=True, text=True)
                    self.messages.insert('end',"Nginx process stopped.\n")
                except subprocess.CalledProcessError as e:
                    self.messages.insert('end',f"Error: {e.stderr}")

        # Start nginx in a detached background cmd process
        if os.path.exists(nginx_executable):
            nginx_dir = os.path.dirname(nginx_executable)
            os.chdir(nginx_dir)
            try:
                cmd = f'start /B cmd /c "{nginx_executable}"'
                subprocess.Popen(cmd, shell=True)
                self.messages.insert('end',"Nginx started.\n")
            except Exception as e:
                self.messages.insert('end',f"Error starting nginx: {e}\n")
        else:
            self.messages.insert('end',"Error: nginx.exe file not found.\n")

    def create_csr(self):
        key_file_path = self.key_path_input.get().strip()
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        req = crypto.X509Req()
        req.get_subject().CN = self.common_name_input.get().strip()
        req.get_subject().O = self.org_input.get().strip()
        req.get_subject().OU = self.dept_input.get().strip()
        req.get_subject().L = self.city_input.get().strip()
        req.get_subject().ST = self.state_input.get().strip()
        req.get_subject().C = self.country_input.get().strip()

        san_list = [x.strip() for x in re.split(r'[,\s]+', self.sans_input.get("1.0", END)) if x.strip()]
        if san_list:
            san_string = ", ".join(f"DNS:{san}" for san in san_list)
            req.add_extensions([crypto.X509Extension("subjectAltName".encode(), False, san_string.encode())])

        req.set_pubkey(key)
        req.sign(key, "sha256")

        private_key_directory = os.path.dirname(key_file_path)
        csr_common_name = self.common_name_input.get().strip().replace("*", "wildcard")  # Replace * with wildcard if present
        csr_path = os.path.join(private_key_directory, f"{csr_common_name}.csr")

        # Rename the current certificate and private key
        current_date = datetime.now().strftime("%d%m%Y")
        renamed_cert_path = f"{self.cert_path_input.get().strip()}.bak.{current_date}"
        renamed_key_path = f"{key_file_path}.bak.{current_date}"

        if os.path.exists(self.cert_path_input.get().strip()):
            shutil.move(self.cert_path_input.get().strip(), renamed_cert_path)
        if os.path.exists(key_file_path):
            shutil.move(key_file_path, renamed_key_path)

        with open(csr_path, "wb") as csr_file:
            csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        with open(key_file_path, "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        self.messages.insert('end', "CSR and private key generated.\n")
        self.messages.see('end')

        try:
            subprocess.Popen(["notepad.exe", csr_path])
        except Exception as e:
            self.messages.insert('end', f"Error: Failed to open CSR in Notepad. {str(e)}\n")
            self.messages.see('end')

    def backup_from_input_fields(self):
        cert_path = self.cert_path_input.get()
        key_path = self.key_path_input.get()

        # Rename the current certificate and private key
        current_date = datetime.now().strftime("%d%m%Y")
        renamed_cert_path = f"{cert_path}.bak.{current_date}"
        renamed_key_path = f"{key_path}.bak.{current_date}"

        if os.path.exists(cert_path):
            try:
                shutil.move(cert_path, renamed_cert_path)
                self.messages.insert(tk.END, f"Backed up certificate to {renamed_cert_path}\n")
            except Exception as e:
                self.messages.insert(tk.END, f"Error backing up certificate: {e}\n")
        if os.path.exists(key_path):
            try:
                shutil.move(key_path, renamed_key_path)
                self.messages.insert(tk.END, f"Backed up key to {renamed_key_path}\n")
            except Exception as e:
                self.messages.insert(tk.END, f"Error backing up key: {e}\n")

    def import_certificate(self):
        cert_file_path = self.cert_path_input.get()
        certificate_path = filedialog.askopenfilename(title="Select the Certificate file", filetypes=[("Certificate files", "*.crt;*.pem;*.cer")])
        if not certificate_path:
            self.messages.insert(tk.END, "No certificate file selected.\n")
            return

        try:
            shutil.copy(certificate_path, cert_file_path)
            self.messages.insert(tk.END, "Certificate imported.\n")
        except Exception as e:
            self.messages.insert(tk.END, f"Error: Failed to import certificate. {str(e)}\n")

    def open_pfx_window(self):
        global pfx_window
        pfx_window = tk.Toplevel(root)
        pfx_window.title("Create PFX")
        pfx_window_width = 320
        pfx_window_height = 320
        pfx_window.geometry("{}x{}+{}+{}".format(pfx_window_width, pfx_window_height,
                                                root.winfo_rootx() + root.winfo_width() + 10,
                                                root.winfo_rooty()))
        pfx_window.resizable(False, False)
        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        pfx_window.iconbitmap(icon_ico)
        
        # Use a custom font style for labels and buttons
        font_style = ("Times New Roman", 12, "bold")

        cert_file_label = ttk.Label(pfx_window, text="Certificate file:", font=font_style)
        cert_file_label.pack(pady=(20, 5))

        cert_file_input = ttk.Entry(pfx_window)
        create_context_menu(cert_file_input)
        cert_file_input.pack(pady=(0, 10))

        browse_cert_button = ttk.Button(pfx_window, text="Choose Cert", command=lambda: self.browse_cert_file(cert_file_input))
        browse_cert_button.pack(pady=(0, 20))

        key_file_label = ttk.Label(pfx_window, text="Private key file:", font=font_style)
        key_file_label.pack(pady=(0, 5))

        key_file_input = ttk.Entry(pfx_window)
        create_context_menu(key_file_input)
        key_file_input.pack(pady=(0, 10))

        browse_key_button = ttk.Button(pfx_window, text="Choose Key", command=lambda: self.browse_key_file(key_file_input))
        browse_key_button.pack(pady=(0, 20))

        create_pfx_button = ttk.Button(pfx_window, text="Generate", command=lambda: self.create_pfx(cert_file_input.get(), key_file_input.get(), pfx_window))
        create_pfx_button.pack(pady=(0, 20))

    def browse_cert_file(self, cert_file_input):
        cert_file_path = filedialog.askopenfilename(filetypes=[("Certificate files", "*.crt;*.pem;*.cer")], title="Select certificate file")
        cert_file_input.delete(0, tk.END)
        cert_file_input.insert(0, cert_file_path)

    def browse_key_file(self, key_file_input):
        key_file_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key;*.pem")], title="Select key file")
        key_file_input.delete(0, tk.END)
        key_file_input.insert(0, key_file_path)

    def create_pfx(self, cert_file, key_file, pfx_window):
        # Check if cert_file and key_file are valid
        if not os.path.isfile(cert_file) or not os.path.isfile(key_file):
            messagebox.showerror("Error", "Invalid certificate or private key file.")
            return

        # Prompt user for password
        password = simpledialog.askstring("Password", "Enter password for PFX file:", show="*", parent=pfx_window)
        if not password:
            return

        # Read the certificate and private key files
        with open(cert_file, "rb") as cert_file_handle:
            cert_data = cert_file_handle.read()

        with open(key_file, "rb") as key_file_handle:
            key_data = key_file_handle.read()

        # Load the certificate and private key
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

        # Create PFX file
        output_pfx_file = os.path.splitext(cert_file)[0] + ".pfx"

        try:
            pfx = crypto.PKCS12()
            pfx.set_certificate(cert)
            pfx.set_privatekey(key)
            pfx_data = pfx.export(password)

            with open(output_pfx_file, "wb") as pfx_file_handle:
                pfx_file_handle.write(pfx_data)

            messagebox.showinfo("Success", f"PFX file created at {output_pfx_file}")

        except Exception as e:
            messagebox.showerror("Error", f"Error creating PFX file: {str(e)}")

            # Close the pfx_window
        pfx_window.destroy()

def open_apache_window():
    # Creates a toplevel widget.
    global _top04, _w04
    _top04 = tk.Toplevel(root)
    _w04 = ApacheToplevel(_top04)

class ApacheToplevel:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''


        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 608
        window_height = 599

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("B.A.S.K.")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        self.apache_bin = None
        self.title_1 = ttk.Label(self.top)
        self.title_1.place(relx=0.115, rely=0.0, height=75, width=469)
        self.title_1.configure(font="-family {Times New Roman} -size 36 -weight bold")
        self.title_1.configure(relief="flat")
        self.title_1.configure(anchor='w')
        self.title_1.configure(justify='left')
        self.title_1.configure(text='''Apache SSL Installer''')
        self.title_1.configure(compound='left')
        self.common_name_label_1 = ttk.Label(self.top)
        self.common_name_label_1.place(relx=0.026, rely=0.134, height=30
                , width=141)
        self.common_name_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.common_name_label_1.configure(relief="flat")
        self.common_name_label_1.configure(anchor='w')
        self.common_name_label_1.configure(justify='left')
        self.common_name_label_1.configure(text='''Common Name:''')
        self.common_name_label_1.configure(compound='left')
        self.org_label_1 = ttk.Label(self.top)
        self.org_label_1.place(relx=0.058, rely=0.195, height=30, width=118)
        self.org_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.org_label_1.configure(relief="flat")
        self.org_label_1.configure(anchor='w')
        self.org_label_1.configure(justify='left')
        self.org_label_1.configure(text='''Organization:''')
        self.org_label_1.configure(compound='left')
        self.dept_label_1 = ttk.Label(self.top)
        self.dept_label_1.place(relx=0.077, rely=0.257, height=28, width=109)
        self.dept_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.dept_label_1.configure(relief="flat")
        self.dept_label_1.configure(anchor='w')
        self.dept_label_1.configure(justify='left')
        self.dept_label_1.configure(text='''Department:''')
        self.dept_label_1.configure(compound='left')
        self.city_label_1 = ttk.Label(self.top)
        self.city_label_1.place(relx=0.179, rely=0.314, height=29, width=47)
        self.city_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.city_label_1.configure(relief="flat")
        self.city_label_1.configure(anchor='w')
        self.city_label_1.configure(justify='left')
        self.city_label_1.configure(text='''City:''')
        self.city_label_1.configure(compound='left')
        self.state_label_1 = ttk.Label(self.top)
        self.state_label_1.place(relx=0.168, rely=0.377, height=30, width=57)
        self.state_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.state_label_1.configure(relief="flat")
        self.state_label_1.configure(anchor='w')
        self.state_label_1.configure(justify='left')
        self.state_label_1.configure(text='''State:''')
        self.state_label_1.configure(compound='left')
        self.country_label_1 = ttk.Label(self.top)
        self.country_label_1.place(relx=0.128, rely=0.447, height=29, width=81)
        self.country_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.country_label_1.configure(relief="flat")
        self.country_label_1.configure(anchor='w')
        self.country_label_1.configure(justify='left')
        self.country_label_1.configure(text='''Country:''')
        self.country_label_1.configure(compound='left')
        self.sans_label_1 = ttk.Label(self.top)
        self.sans_label_1.place(relx=0.164, rely=0.541, height=30, width=59)
        self.sans_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.sans_label_1.configure(relief="flat")
        self.sans_label_1.configure(anchor='w')
        self.sans_label_1.configure(justify='left')
        self.sans_label_1.configure(text='''SANs:''')
        self.sans_label_1.configure(compound='left')
        self.cert_path_label_1 = ttk.Label(self.top)
        self.cert_path_label_1.place(relx=0.028, rely=0.634, height=29
                , width=143)
        self.cert_path_label_1.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.cert_path_label_1.configure(relief="flat")
        self.cert_path_label_1.configure(anchor='w')
        self.cert_path_label_1.configure(justify='left')
        self.cert_path_label_1.configure(text='''Certificate Path:''')
        self.cert_path_label_1.configure(compound='left')
        self.private_key_path_label = ttk.Label(self.top)
        self.private_key_path_label.place(relx=0.016, rely=0.701, height=29
                , width=151)
        self.private_key_path_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.private_key_path_label.configure(relief="flat")
        self.private_key_path_label.configure(anchor='w')
        self.private_key_path_label.configure(justify='left')
        self.private_key_path_label.configure(text='''Private Key Path:''')
        self.private_key_path_label.configure(compound='left')
        self.messages_1 = ScrolledListBox(self.top)
        self.messages_1.place(relx=0.016, rely=0.768, relheight=0.195
                , relwidth=0.952)
        
        self.messages_1.configure(cursor="xterm")
        
        self.messages_1.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.messages_1.configure(foreground="black")
        
        self.messages_1.configure(selectbackground="#c4c4c4")
        self.messages_1.configure(selectforeground="black")
        self.common_name_input_1 = ttk.Entry(self.top)
        create_context_menu(self.common_name_input_1)
        self.common_name_input_1.place(relx=0.278, rely=0.139, relheight=0.045
                , relwidth=0.339)
        self.common_name_input_1.configure(takefocus="")
        
        self.common_name_input_1_tooltip = \
        ToolTip(self.common_name_input_1, '''Example: bask.com''')

        self.org_input_1 = ttk.Entry(self.top)
        create_context_menu(self.org_input_1)
        self.org_input_1.place(relx=0.28, rely=0.2, relheight=0.045
                , relwidth=0.339)
        self.org_input_1.configure(takefocus="")
        
        self.org_input_1_tooltip = \
        ToolTip(self.org_input_1, '''Example: Bask''')

        self.dept_input_1 = ttk.Entry(self.top)
        create_context_menu(self.dept_input_1)
        self.dept_input_1.place(relx=0.28, rely=0.26, relheight=0.045
                , relwidth=0.339)
        self.dept_input_1.configure(takefocus="")
        
        self.dept_input_1_tooltip = \
        ToolTip(self.dept_input_1, '''Example: IT''')

        self.city_input_1 = ttk.Entry(self.top)
        create_context_menu(self.city_input_1)
        self.city_input_1.place(relx=0.28, rely=0.317, relheight=0.045
                , relwidth=0.339)
        self.city_input_1.configure(takefocus="")
        
        self.city_input_1_tooltip = \
        ToolTip(self.city_input_1, '''Example: Dallas''')

        self.state_input_1 = ttk.Entry(self.top)
        create_context_menu(self.state_input_1)
        self.state_input_1.place(relx=0.28, rely=0.384, relheight=0.045
                , relwidth=0.339)
        self.state_input_1.configure(takefocus="")
        self.state_input_1.configure(cursor="ibeam")
        self.state_input_1_tooltip = \
        ToolTip(self.state_input_1, '''Example: Texas''')

        self.country_input_1 = ttk.Entry(self.top)
        create_context_menu(self.country_input_1)
        self.country_input_1.place(relx=0.28, rely=0.451, relheight=0.045
                , relwidth=0.339)
        self.country_input_1.configure(takefocus="")
        self.country_input_1.configure(cursor="ibeam")
        self.country_input_1_tooltip = \
        ToolTip(self.country_input_1, '''2 Letters, Example: US''')

        self.sans_input_1 = ScrolledText(self.top)
        create_context_menu(self.sans_input_1)
        self.sans_input_1.place(relx=0.281, rely=0.518, relheight=0.102
                , relwidth=0.339)
        
        self.sans_input_1.configure(font="-family {Times New Roman} -size 12")
        self.sans_input_1.configure(foreground="black")
        self.sans_input_1.configure(highlightbackground="#d9d9d9")
        self.sans_input_1.configure(highlightcolor="black")
        self.sans_input_1.configure(insertbackground="black")
        self.sans_input_1.configure(insertborderwidth="3")
        self.sans_input_1.configure(selectbackground="#c4c4c4")
        self.sans_input_1.configure(selectforeground="black")
        self.sans_input_1.configure(wrap="none")
        self.cert_path_input_1 = ttk.Entry(self.top)
        create_context_menu(self.cert_path_input_1)
        self.cert_path_input_1.place(relx=0.28, rely=0.634, relheight=0.045
                , relwidth=0.339)
        self.cert_path_input_1.configure(takefocus="")
        self.cert_path_input_1.configure(cursor="ibeam")
        self.key_path_input_1 = ttk.Entry(self.top)
        create_context_menu(self.key_path_input_1)
        self.key_path_input_1.place(relx=0.28, rely=0.701, relheight=0.045
                , relwidth=0.339)
        self.key_path_input_1.configure(takefocus="")
        
        self.create_csr_button_2 = ttk.Button(self.top)
        self.create_csr_button_2.place(relx=0.691, rely=0.2, height=29
                , width=124)
        self.create_csr_button_2.configure(takefocus="")
        self.create_csr_button_2.configure(text='''Create CSR''')
        self.create_csr_button_2.configure(command= lambda: self.create_csr())
        self.create_csr_button_2.configure(compound='left')
        self.import_certficate_button_1 = ttk.Button(self.top)
        self.import_certficate_button_1.place(relx=0.691, rely=0.317, height=29
                , width=124)
        self.import_certficate_button_1.configure(takefocus="")
        self.import_certficate_button_1.configure(text='''Import Certificate''')
        self.import_certficate_button_1.configure(command= lambda: self.import_certificate())
        self.import_certficate_button_1.configure(compound='left')
        self.restart_apache_button = ttk.Button(self.top)
        self.restart_apache_button.place(relx=0.691, rely=0.451, height=29
                , width=124)
        self.restart_apache_button.configure(takefocus="")
        self.restart_apache_button.configure(text='''Restart Apache''')
        self.restart_apache_button.configure(command= lambda: self.restart_apache(self.apache_bin, self.messages_1))
        self.restart_apache_button.configure(compound='left')
        self.create_pfx_button_1 = ttk.Button(self.top)
        self.create_pfx_button_1.place(relx=0.691, rely=0.584, height=29
                , width=124)
        self.create_pfx_button_1.configure(takefocus="")
        self.create_pfx_button_1.configure(text='''Create PFX''')
        self.create_pfx_button_1.configure(command= lambda: self.open_pfx_window())
        self.create_pfx_button_1.configure(compound='left')

        apache_installed = messagebox.askyesno("Confirmation", "Is Apache installed?")
        if apache_installed:
            self.find_info(self.cert_path_input_1, self.key_path_input_1, self.messages_1)
        else:
            messagebox.showwarning("Warning", "Some features might not work correctly without Apache installed.")

    def find_info(self, cert_path_input_1, key_path_input_1, messages_1):
        # Define patterns
        ssl_cert_pattern = re.compile(r"^\s*SSLCertificateFile\s+(.*)\s*$")
        ssl_key_pattern = re.compile(r"^\s*SSLCertificateKeyFile\s+(.*)\s*$")

        # Find Apache folder
        apache_folder = None
        root_dir = Path('C:/')
        
        start_time = tm.time()  # start time
        timeout = 10  # time limit in seconds

        for path in root_dir.glob('**/*'):
            if tm.time() - start_time > timeout:  # if time limit exceeded
                break
            if path.is_dir() and path.name.lower().startswith('apache') and len(path.parts) - len(root_dir.parts) < 3: #limiting the depth to 2 levels.
                apache_folder = path
                break

        # if apache_folder is None:
        #     messagebox.showwarning("Warning", "Apache is not installed, some features may not work")
        #     return None, None, None, None

        # Find ssl.conf file
        ssl_conf_file = None
        for dirpath, dirnames, filenames in os.walk(apache_folder):
            for filename in filenames:
                if 'ssl' in filename.lower() and filename.endswith('.conf'):
                    ssl_conf_file = os.path.join(dirpath, filename)
                    break
            if ssl_conf_file:
                break

        if ssl_conf_file is None:
            messagebox.showerror("Error", "SSL configuration file not found")
            return None, None, None, None

        # Extract certificate and private key location
        cert_path = None
        key_path = None
        with open(ssl_conf_file, 'r') as file:
            for line in file:
                cert_match = ssl_cert_pattern.match(line)
                key_match = ssl_key_pattern.match(line)

                if cert_match:
                    cert_path = cert_match.group(1).strip()

                if key_match:
                    key_path = key_match.group(1).strip()

                if cert_path and key_path:
                    break

        # Fill in the boxes for cert_path_input_1 and key_path_input_1
        if cert_path and key_path:
            cert_path_input_1.delete(0, tk.END)
            cert_path_input_1.insert(0, cert_path.strip('"'))  # Strip double quotes
            key_path_input_1.delete(0, tk.END)
            key_path_input_1.insert(0, key_path.strip('"'))  # Strip double quotes
            self.apache_bin = os.path.join(apache_folder, 'bin')  # Assign to instance variable
            messages_1.insert(tk.END, f"Apache binary path: {self.apache_bin}\n")

        return cert_path, key_path, apache_folder, self.apache_bin  # Return self.apache_bin

    def restart_apache(self, apache_bin, messages_1):
        messages_1.insert(tk.END, "Restarting the Apache Service...\n")
        try:
            output = subprocess.check_output([os.path.join(self.apache_bin, 'httpd.exe'), '-k', 'restart'], stderr=subprocess.STDOUT, shell=True)
            messages_1.insert(tk.END, output.decode())
        except subprocess.CalledProcessError as e:
            messages_1.insert(tk.END, e.output.decode())
        command = f"start /b cmd /c {os.path.join(self.apache_bin, 'httpd.exe')} -k restart"
        subprocess.Popen(command, shell=True)

    def create_csr(self):
        key_file_path = self.key_path_input_1.get().strip()
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        req = crypto.X509Req()
        req.get_subject().CN = self.common_name_input_1.get().strip()
        req.get_subject().O = self.org_input_1.get().strip()
        req.get_subject().OU = self.dept_input_1.get().strip()
        req.get_subject().L = self.city_input_1.get().strip()
        req.get_subject().ST = self.state_input_1.get().strip()
        req.get_subject().C = self.country_input_1.get().strip()

        san_list = [x.strip() for x in re.split(r'[,\s]+', self.sans_input_1.get("1.0", tk.END)) if x.strip()]
        if san_list:
            san_string = ", ".join(f"DNS:{san}" for san in san_list)
            req.add_extensions([crypto.X509Extension("subjectAltName".encode(), False, san_string.encode())])

        req.set_pubkey(key)
        req.sign(key, "sha256")

        private_key_directory = os.path.dirname(key_file_path)
        csr_common_name = self.common_name_input_1.get().strip().replace("*", "wildcard")  # Replace * with wildcard if present
        csr_path = os.path.join(private_key_directory, f"{csr_common_name}.csr")

        cert_path = self.cert_path_input_1.get().strip()
        self.backup_from_input_fields(cert_path, key_file_path)

        csr_path = csr_path.replace('"', '')
        with open(csr_path, "wb") as csr_file:
            csr_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        key_file_path = key_file_path.replace('"', '')
        with open(key_file_path, "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        self.messages_1.insert(tk.END, "CSR and private key generated.")

        try:
            subprocess.Popen(["notepad.exe", csr_path])
        except Exception as e:
            self.messages_1.insert(tk.INSERT, f"Error: Failed to open CSR in Notepad. {str(e)}\n")    

    def backup_from_input_fields(self, cert_path, key_file_path):
        cert_path = self.cert_path_input_1.get().strip()
        key_path = self.key_path_input_1.get().strip()

        # Rename the current certificate and private key
        current_date = datetime.now().strftime("%d%m%Y")
        renamed_cert_path = f"{cert_path}.bak.{current_date}"
        renamed_key_path = f"{key_path}.bak.{current_date}"

        if os.path.exists(cert_path):
            shutil.move(cert_path, renamed_cert_path)
        if os.path.exists(key_path):
            shutil.move(key_path, renamed_key_path)

    def import_certificate(self):
        cert_file_path = self.cert_path_input_1.get().strip()
        certificate_path = filedialog.askopenfilename(title="Select the Certificate file", filetypes=[("Certificate files", "*.crt;*.pem;*.cer")])
        if not certificate_path:
            self.messages_1.insert(tk.END, "No certificate file selected.\n")
            return

        try:
            shutil.copy(certificate_path, cert_file_path)
            self.messages_1.insert(tk.END, "Certificate imported.\n")
        except Exception as e:
            self.messages_1.insert(tk.END, f"Error: Failed to import certificate. {str(e)}\n")

    def open_pfx_window(self):
        global pfx_window
        pfx_window = tk.Toplevel(root)
        pfx_window.title("Create PFX")
        pfx_window_width = 320
        pfx_window_height = 320
        pfx_window.geometry("{}x{}+{}+{}".format(pfx_window_width, pfx_window_height,
                                                root.winfo_rootx() + root.winfo_width() + 10,
                                                root.winfo_rooty()))
        pfx_window.resizable(False, False)
        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        pfx_window.iconbitmap(icon_ico)
    
        # Use a custom font style for labels and buttons
        font_style = ("Times New Roman", 12, "bold")

        cert_file_label = ttk.Label(pfx_window, text="Certificate file:", font=font_style, style='TLabel')
        cert_file_label.pack(pady=(20, 5))

        pfx_cert_file_input = ttk.Entry(pfx_window, style='TEntry')
        create_context_menu(pfx_cert_file_input)
        pfx_cert_file_input.pack(pady=(0, 10))

        browse_cert_button = ttk.Button(pfx_window, text="Choose Cert", style='TButton', command=lambda: browse_cert_file(pfx_cert_file_input))
        browse_cert_button.pack(pady=(0, 20))

        key_file_label = ttk.Label(pfx_window, text="Private key file:", font=font_style, style='TLabel')
        key_file_label.pack(pady=(0, 5))

        pfx_key_file_input = ttk.Entry(pfx_window, style='TEntry')
        create_context_menu(pfx_key_file_input)
        pfx_key_file_input.pack(pady=(0, 10))

        browse_key_button = ttk.Button(pfx_window, text="Choose Key", style='TButton', command=lambda: browse_key_file(pfx_key_file_input))
        browse_key_button.pack(pady=(0, 20))

        create_pfx_button = ttk.Button(pfx_window, text="Generate", style='TButton', command=lambda: create_pfx(pfx_cert_file_input.get(), pfx_key_file_input.get(), pfx_window, self))
        create_pfx_button.pack(pady=(0, 20))

        def browse_cert_file(cert_file_input):
            cert_file_path = filedialog.askopenfilename(filetypes=[("Certificate files", "*.crt;*.pem;*.cer")], title="Select certificate file")
            cert_file_input.delete(0, tk.END)
            cert_file_input.insert(0, cert_file_path)
        
        def browse_key_file(key_file_input):
            key_file_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key;*.pem")], title="Select key file")
            key_file_input.delete(0, tk.END)
            key_file_input.insert(0, key_file_path)

        def create_pfx(pfx_cert_file, pfx_key_file, pfx_window, self):
            # Check if cert_file and key_file are valid
            if not os.path.isfile(pfx_cert_file) or not os.path.isfile(pfx_key_file):
                messagebox.showerror("Error", "Invalid certificate or private key file.")
                return

            # Prompt user for password
            password = simpledialog.askstring("Password", "Enter password for PFX file:", show="*", parent=pfx_window)
            if not password:
                return

            # Read the certificate and private key files
            with open(pfx_cert_file, "rb") as cert_file_handle:
                cert_data = cert_file_handle.read()

            with open(pfx_key_file, "rb") as key_file_handle:
                key_data = key_file_handle.read()

            # Load the certificate and private key
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

            # Create PFX file
            output_pfx_file = os.path.splitext(pfx_cert_file)[0] + ".pfx"

            try:
                pfx = crypto.PKCS12()
                pfx.set_certificate(cert)
                pfx.set_privatekey(key)
                pfx_data = pfx.export(password)

                with open(output_pfx_file, "wb") as pfx_file_handle:
                    pfx_file_handle.write(pfx_data)

                messagebox.showinfo("Success", f"PFX file created at {output_pfx_file}")

            except Exception as e:
                messagebox.showerror("Error", f"Error creating PFX file: {str(e)}")

            # Close the pfx_window
            pfx_window.destroy()

        

def open_csr_window():
    # Creates a toplevel widget.
    global _top05, _w05
    _top05 = tk.Toplevel(root)
    _w05 = CSRToplevel(_top05)

class CSRToplevel:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        self.inf_file_path = ''
        self.csr_file_path = ''
        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 431
        window_height = 470

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("B.A.S.K.")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        
        self.common_name_label_2 = ttk.Label(self.top)
        self.common_name_label_2.place(relx=0.023, rely=0.043, height=27
                , width=139)
        self.common_name_label_2.configure(font="-family {Times New Roman} -size 15 -weight bold")
        self.common_name_label_2.configure(relief="flat")
        self.common_name_label_2.configure(anchor='w')
        self.common_name_label_2.configure(justify='left')
        self.common_name_label_2.configure(text='''Common Name:''')
        self.common_name_label_2.configure(compound='left')
        self.TLabel1 = ttk.Label(self.top)
        self.TLabel1.place(relx=0.06, rely=0.149, height=27, width=125)
        self.TLabel1.configure(font="-family {Times New Roman} -size 15 -weight bold")
        self.TLabel1.configure(relief="flat")
        self.TLabel1.configure(anchor='w')
        self.TLabel1.configure(justify='left')
        self.TLabel1.configure(text='''Organization:''')
        self.TLabel1.configure(compound='left')
        self.dept_label_2 = tk.Label(self.top)
        self.dept_label_2.place(relx=0.079, rely=0.243, height=28, width=114)
        
        self.dept_label_2.configure(anchor='w')
        
        self.dept_label_2.configure(compound='left')
        
        self.dept_label_2.configure(font="-family {Times New Roman} -size 15 -weight bold")
        
        self.dept_label_2.configure(text='''Department:''')
        self.city_label_2 = ttk.Label(self.top)
        self.city_label_2.place(relx=0.232, rely=0.342, height=27, width=54)
        
        self.city_label_2.configure(font="-family {Times New Roman} -size 15 -weight bold")
        self.city_label_2.configure(relief="flat")
        self.city_label_2.configure(anchor='w')
        self.city_label_2.configure(justify='left')
        self.city_label_2.configure(text='''City:''')
        self.city_label_2.configure(compound='left')
        self.state_label_2 = ttk.Label(self.top)
        self.state_label_2.place(relx=0.213, rely=0.446, height=24, width=64)
        
        self.state_label_2.configure(font="-family {Times New Roman} -size 15 -weight bold")
        self.state_label_2.configure(relief="flat")
        self.state_label_2.configure(anchor='w')
        self.state_label_2.configure(justify='left')
        self.state_label_2.configure(text='''State:''')
        self.state_label_2.configure(compound='left')
        self.country_label_2 = ttk.Label(self.top)
        self.country_label_2.place(relx=0.165, rely=0.563, height=24, width=85)
        
        self.country_label_2.configure(font="-family {Times New Roman} -size 15 -weight bold")
        self.country_label_2.configure(relief="flat")
        self.country_label_2.configure(anchor='w')
        self.country_label_2.configure(justify='left')
        self.country_label_2.configure(text='''Country:''')
        self.country_label_2.configure(compound='left')
        self.sans_label_2 = ttk.Label(self.top)
        self.sans_label_2.place(relx=0.211, rely=0.66, height=45, width=64)
        
        self.sans_label_2.configure(font="-family {Times New Roman} -size 15 -weight bold")
        self.sans_label_2.configure(relief="flat")
        self.sans_label_2.configure(anchor='w')
        self.sans_label_2.configure(justify='left')
        self.sans_label_2.configure(text='''SANs:''')
        self.sans_label_2.configure(compound='left')

        self.common_name_input_2 = ttk.Entry(self.top)
        create_context_menu(self.common_name_input_2)
        self.common_name_input_2.place(relx=0.39, rely=0.040, relheight=0.070
                , relwidth=0.478)
        self.common_name_input_2.configure(takefocus="")
        self.common_name_input_2.configure(cursor="ibeam")
        self.common_name_input_2_tooltip = \
        ToolTip(self.common_name_input_2, '''Example: bask.com''')

        self.org_input_2 = ttk.Entry(self.top)
        create_context_menu(self.org_input_2)
        self.org_input_2.place(relx=0.394, rely=0.140, relheight=0.070
                , relwidth=0.478)
        self.org_input_2.configure(takefocus="")
        self.org_input_2.configure(cursor="ibeam")
        self.org_input_2_tooltip = \
        ToolTip(self.org_input_2, '''Example: Bask''')

        self.dept_input_2 = ttk.Entry(self.top)
        create_context_menu(self.dept_input_2)
        self.dept_input_2.place(relx=0.394, rely=0.240, relheight=0.070
                , relwidth=0.478)
        self.dept_input_2.configure(takefocus="")
        self.dept_input_2.configure(cursor="ibeam")
        self.dept_input_2_tooltip = \
        ToolTip(self.dept_input_2, '''Example: IT''')

        self.city_input_2 = ttk.Entry(self.top)
        create_context_menu(self.city_input_2)
        self.city_input_2.place(relx=0.394, rely=0.34, relheight=0.070
                , relwidth=0.478)
        self.city_input_2.configure(takefocus="")
        self.city_input_2.configure(cursor="ibeam")
        self.city_input_2_tooltip = \
        ToolTip(self.city_input_2, '''Example: Orem''')

        self.state_input_2 = ttk.Entry(self.top)
        create_context_menu(self.state_input_2)
        self.state_input_2.place(relx=0.394, rely=0.447, relheight=0.070
                , relwidth=0.478)
        self.state_input_2.configure(takefocus="")
        self.state_input_2.configure(cursor="ibeam")
        self.state_input_2_tooltip = \
        ToolTip(self.state_input_2, '''Example: Utah''')

        self.country_input_2 = ttk.Entry(self.top)
        create_context_menu(self.country_input_2)
        self.country_input_2.place(relx=0.394, rely=0.553, relheight=0.070
                , relwidth=0.478)
        self.country_input_2.configure(takefocus="")
        self.country_input_2.configure(cursor="ibeam")
        self.country_input_2_tooltip = \
        ToolTip(self.country_input_2, '''2 Letters, Example: US''')

        self.sans_input_2 = ScrolledText(self.top)
        create_context_menu(self.sans_input_2)
        self.sans_input_2.place(relx=0.394, rely=0.638, relheight=0.138
                , relwidth=0.478)
        
        self.sans_input_2.configure(font="-family {Times New Roman} -size 12")
        self.sans_input_2.configure(insertbackground="black")
        self.sans_input_2.configure(insertborderwidth="3")
        self.sans_input_2.configure(selectbackground="#c4c4c4")
        self.sans_input_2.configure(selectforeground="black")
        self.sans_input_2.configure(wrap="none")
        self.generate_csr_button = ttk.Button(self.top)
        self.generate_csr_button.place(relx=0.348, rely=0.851, height=29
                , width=108)
        self.generate_csr_button.configure(takefocus="")
        self.generate_csr_button.configure(text='''Generate CSR''')
        self.generate_csr_button.configure(command=lambda: self.create_csr())
        self.generate_csr_button.configure(compound='left')

    def select_csr_and_inf_file(self):
        """Select a file to save the CSR and INF."""
        filename = filedialog.asksaveasfilename(initialdir=".", title="Save CSR File", defaultextension=".csr", filetypes=[("CSR Files", "*.csr")])
        if filename:
            self.csr_file_path = os.path.normpath(filename)
            self.inf_file_path = os.path.splitext(self.csr_file_path)[0] + '.inf'

    def create_csr(self):
        """Create a CSR file."""
        self.select_csr_and_inf_file()
        if not self.csr_file_path:
            messagebox.showwarning("No File Location Selected", "File creation was cancelled.")
            return
        # Generate the INF file
        inf_contents = f"""[Version]
            Signature="$Windows NT$"

            [NewRequest]
            Subject = "CN={self.common_name_input_2.get()},O={self.org_input_2.get()},OU={self.dept_input_2.get()},L={self.city_input_2.get()},S={self.state_input_2.get()},C={self.country_input_2.get()}"
            KeySpec = 1
            KeyLength = 2048
            HashAlgorithm = SHA256
            Exportable = TRUE
            MachineKeySet = TRUE
            SMIME = FALSE
            PrivateKeyArchive = FALSE
            UserProtected = FALSE
            UseExistingKeySet = FALSE
            ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
            ProviderType = 12
            RequestType = PKCS10
            KeyUsage = 0xa0

            [EnhancedKeyUsageExtension]
            OID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication
            """
        with open(self.inf_file_path, "w") as inf_file:
            inf_file.write(inf_contents)
            
        # Generate the CSR using Certreq.exe
        csr_cmd = ["certreq", "-new", self.inf_file_path, self.csr_file_path]
        try:
            result = subprocess.run(csr_cmd, capture_output=True, check=True, text=True)
        except subprocess.CalledProcessError as e:
            print("Error: ", e.returncode, e.output, e.stderr)
        if result.returncode != 0:
            messagebox.showerror("Error", f"An error occurred while creating the CSR:\n{result.stderr}")
        else:
            messagebox.showinfo("CSR Created", f"CSR file created: {self.csr_file_path}")

            subprocess.Popen(["notepad", self.csr_file_path])   

def open_StandWildToplevel():
    global _top06, _w06
    _top06 = tk.Toplevel(root)
    _w06 = StandWildToplevel(_top06)

class StandWildToplevel:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        
        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 431
        window_height = 470

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Standard or Wilcard CSR Generator")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

      
        self.common_name_label = ttk.Label(self.top)
        self.common_name_label.place(relx=0.07, rely=0.021, height=24, width=149)

        
        self.common_name_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.common_name_label.configure(relief="flat")
        self.common_name_label.configure(anchor='w')
        self.common_name_label.configure(justify='left')
        self.common_name_label.configure(text='''Common Name:''')
        self.common_name_label.configure(compound='left')
        self.org_label = ttk.Label(self.top)
        self.org_label.place(relx=0.116, rely=0.111, height=24, width=127)
        
        self.org_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.org_label.configure(relief="flat")
        self.org_label.configure(anchor='w')
        self.org_label.configure(justify='left')
        self.org_label.configure(text='''Organization:''')
        self.org_label.configure(compound='left')
        self.dept_label = ttk.Label(self.top)
        self.dept_label.place(relx=0.137, rely=0.2, height=24, width=110)
        
        self.dept_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.dept_label.configure(relief="flat")
        self.dept_label.configure(anchor='w')
        self.dept_label.configure(justify='left')
        self.dept_label.configure(text='''Department:''')
        self.dept_label.configure(compound='left')
        self.city_label = ttk.Label(self.top)
        self.city_label.place(relx=0.283, rely=0.289, height=24, width=46)
        
        self.city_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.city_label.configure(relief="flat")
        self.city_label.configure(anchor='w')
        self.city_label.configure(justify='left')
        self.city_label.configure(text='''City:''')
        self.city_label.configure(compound='left')
        self.state_label = ttk.Label(self.top)
        self.state_label.place(relx=0.267, rely=0.379, height=24, width=54)
        
        self.state_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.state_label.configure(relief="flat")
        self.state_label.configure(anchor='w')
        self.state_label.configure(justify='left')
        self.state_label.configure(text='''State:''')
        self.state_label.configure(compound='left')
        self.country_input = ttk.Label(self.top)
        create_context_menu(self.country_input)
        self.country_input.place(relx=0.211, rely=0.466, height=30, width=79)
        
        self.country_input.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.country_input.configure(relief="flat")
        self.country_input.configure(anchor='w')
        self.country_input.configure(justify='left')
        self.country_input.configure(text='''Country:''')
        self.country_input.configure(compound='left')
        self.private_key_name_label = ttk.Label(self.top)
        self.private_key_name_label.place(relx=0.023, rely=0.645, height=24
                , width=166)
        
        self.private_key_name_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.private_key_name_label.configure(relief="flat")
        self.private_key_name_label.configure(anchor='w')
        self.private_key_name_label.configure(justify='left')
        self.private_key_name_label.configure(text='''Private Key Name:''')
        self.private_key_name_label.configure(compound='left')
        self.csr_name_label = ttk.Label(self.top)
        self.csr_name_label.place(relx=0.155, rely=0.555, height=24, width=110)
        
        self.csr_name_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.csr_name_label.configure(relief="flat")
        self.csr_name_label.configure(anchor='w')
        self.csr_name_label.configure(justify='left')
        self.csr_name_label.configure(text='''CSR Name:''')
        self.csr_name_label.configure(compound='left')
        self.result = ScrolledListBox(self.top)
        self.result.place(relx=0.032, rely=0.791, relheight=0.1, relwidth=0.954)

        
        self.result.configure(cursor="xterm")
        self.result.configure(disabledforeground="#a3a3a3")
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(foreground="black")
        
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.371, rely=0.721, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=self.generate)
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.371, rely=0.911, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=self.copy_result)
        self.copy_button.configure(compound='left')
        self.common_name_input = ttk.Entry(self.top)
        create_context_menu(self.common_name_input)
        self.common_name_input.place(relx=0.418, rely=0.021, relheight=0.068
                , relwidth=0.478)
        self.common_name_input.configure(takefocus="")
        self.org_input = ttk.Entry(self.top)
        create_context_menu(self.org_input)
        self.org_input.place(relx=0.418, rely=0.111, relheight=0.068
                , relwidth=0.478)
        self.org_input.configure(takefocus="")
        self.org_input.configure(cursor="ibeam")
        self.dept_input = ttk.Entry(self.top)
        create_context_menu(self.dept_input)
        self.dept_input.place(relx=0.418, rely=0.2, relheight=0.068, relwidth=0.478)

        self.dept_input.configure(takefocus="")
        self.city_input = ttk.Entry(self.top)
        create_context_menu(self.city_input)
        self.city_input.place(relx=0.418, rely=0.289, relheight=0.068
                , relwidth=0.478)
        self.city_input.configure(takefocus="")
        self.city_input.configure(cursor="ibeam")
        self.state_input = ttk.Entry(self.top)
        create_context_menu(self.state_input)
        self.state_input.place(relx=0.418, rely=0.379, relheight=0.068
                , relwidth=0.478)
        self.state_input.configure(takefocus="")
        self.state_input.configure(cursor="ibeam")
        self.country_input = ttk.Entry(self.top)
        create_context_menu(self.country_input)
        self.country_input.place(relx=0.418, rely=0.466, relheight=0.068
                , relwidth=0.478)
        self.country_input.configure(takefocus="")
        self.country_input.configure(cursor="ibeam")
        self.csr_name_input = ttk.Entry(self.top)
        create_context_menu(self.csr_name_input)
        self.csr_name_input.place(relx=0.418, rely=0.555, relheight=0.068
                , relwidth=0.478)
        self.csr_name_input.configure(takefocus="")
        self.csr_name_input.configure(cursor="ibeam")
        self.priv_key_name_input = ttk.Entry(self.top)
        create_context_menu(self.priv_key_name_input)
        self.priv_key_name_input.place(relx=0.418, rely=0.645, relheight=0.068
                , relwidth=0.478)
        self.priv_key_name_input.configure(takefocus="")
        self.priv_key_name_input.configure(cursor="ibeam")
        self.menubar = tk.Menu(top, font="-family {Times New Roman} -size 12"
                ,bg=_bgcolor, fg=_fgcolor)
        top.configure(menu = self.menubar)

    def generate(self):
        command = "openssl req -new -newkey rsa:2048 -nodes -keyout " + self.priv_key_name_input.get()
        command += " -out " + self.csr_name_input.get()
        command += " -subj '/C=" + self.country_input.get()
        command += "/ST=" + self.state_input.get()
        command += "/L=" + self.city_input.get()
        command += "/O=" + self.org_input.get()
        command += "/OU=" + self.dept_input.get()
        command += "/CN=" + self.common_name_input.get() + "/'"
        #self.result.set(command)
        self.result.delete(0, tk.END)
        self.result.insert(tk.END, command)
    
    def copy_result(self):
        self.top.clipboard_clear()
        contents = "\n".join(self.result.get(0, tk.END))
        self.top.clipboard_append(contents)

def open_ucc():
    global _top07, _w07
    _top07 = tk.Toplevel(root)
    _w07 = UCCToplevel(_top07)

class UCCToplevel:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 484
        window_height = 571

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("UCC CSR Generator")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        
        self.common_name_label = ttk.Label(self.top)
        self.common_name_label.place(relx=0.072, rely=0.026, height=29
                , width=155)
        
        self.common_name_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.common_name_label.configure(relief="flat")
        self.common_name_label.configure(anchor='w')
        self.common_name_label.configure(justify='left')
        self.common_name_label.configure(text='''Common Name:''')
        self.common_name_label.configure(compound='left')
        self.org_label = ttk.Label(self.top)
        self.org_label.place(relx=0.107, rely=0.109, height=30, width=133)
        
        self.org_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.org_label.configure(relief="flat")
        self.org_label.configure(anchor='w')
        self.org_label.configure(justify='left')
        self.org_label.configure(text='''Organization:''')
        self.org_label.configure(compound='left')
        self.dept_label = ttk.Label(self.top)
        self.dept_label.place(relx=0.128, rely=0.196, height=29, width=122)
        
        self.dept_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.dept_label.configure(relief="flat")
        self.dept_label.configure(anchor='w')
        self.dept_label.configure(justify='left')
        self.dept_label.configure(text='''Department:''')
        self.dept_label.configure(compound='left')
        self.city_label = ttk.Label(self.top)
        self.city_label.place(relx=0.252, rely=0.291, height=29, width=56)
        
        self.city_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.city_label.configure(relief="flat")
        self.city_label.configure(anchor='w')
        self.city_label.configure(justify='left')
        self.city_label.configure(text='''City:''')
        self.city_label.configure(compound='left')
        self.state_label = ttk.Label(self.top)
        self.state_label.place(relx=0.233, rely=0.373, height=28, width=67)
        
        self.state_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.state_label.configure(relief="flat")
        self.state_label.configure(anchor='w')
        self.state_label.configure(justify='left')
        self.state_label.configure(text='''State:''')
        self.state_label.configure(compound='left')
        self.country_label = ttk.Label(self.top)
        self.country_label.place(relx=0.184, rely=0.460, height=29, width=88)
        
        self.country_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.country_label.configure(relief="flat")
        self.country_label.configure(anchor='w')
        self.country_label.configure(justify='left')
        self.country_label.configure(text='''Country:''')
        self.country_label.configure(compound='left')
        self.sans_label = ttk.Label(self.top)
        self.sans_label.place(relx=0.227, rely=0.533, height=29, width=67)
        
        self.sans_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.sans_label.configure(relief="flat")
        self.sans_label.configure(anchor='w')
        self.sans_label.configure(justify='left')
        self.sans_label.configure(text='''SANs:''')
        self.sans_label.configure(compound='left')
        self.csr_name_label = ttk.Label(self.top)
        self.csr_name_label.place(relx=0.134, rely=0.630, height=29, width=112)
        
        self.csr_name_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.csr_name_label.configure(relief="flat")
        self.csr_name_label.configure(anchor='w')
        self.csr_name_label.configure(justify='left')
        self.csr_name_label.configure(text='''CSR Name:''')
        self.csr_name_label.configure(compound='left')
        self.priv_key_label = ttk.Label(self.top)
        self.priv_key_label.place(relx=0.014, rely=0.698, height=29, width=167)
        
        self.priv_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.priv_key_label.configure(relief="flat")
        self.priv_key_label.configure(anchor='w')
        self.priv_key_label.configure(justify='left')
        self.priv_key_label.configure(text='''Private Key Name:''')
        self.priv_key_label.configure(compound='left')
        self.result = ScrolledListBox(self.top)
        self.result.place(relx=0.039, rely=0.82, relheight=0.072, relwidth=0.917)

        self.result.configure(background="white")
        self.result.configure(cursor="xterm")
        self.result.configure(disabledforeground="#a3a3a3")
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(foreground="black")
        self.result.configure(highlightbackground="#d9d9d9")
        self.result.configure(highlightcolor="#d9d9d9")
        self.result.configure(selectbackground="#c4c4c4")
        self.result.configure(selectforeground="black")
        self.common_name_input = ttk.Entry(self.top)
        create_context_menu(self.common_name_input)
        self.common_name_input.place(relx=0.372, rely=0.021, relheight=0.057
                , relwidth=0.459)
        self.common_name_input.configure(takefocus="")
        self.common_name_input.configure(cursor="ibeam")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.372, rely=0.761, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=self.display)
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.372, rely=0.916, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=self.copy_result)
        self.copy_button.configure(compound='left')
        self.org_input = ttk.Entry(self.top)
        create_context_menu(self.org_input)
        self.org_input.place(relx=0.372, rely=0.102, relheight=0.057
                , relwidth=0.459)
        self.org_input.configure(takefocus="")
        self.menubar = tk.Menu(top, font="-family {Times New Roman} -size 12"
                ,bg=_bgcolor, fg=_fgcolor)
        top.configure(menu = self.menubar)

        self.dept_input = ttk.Entry(self.top)
        create_context_menu(self.dept_input)
        self.dept_input.place(relx=0.372, rely=0.194, relheight=0.057
                , relwidth=0.459)
        self.dept_input.configure(takefocus="")
        self.city_input = ttk.Entry(self.top)
        create_context_menu(self.city_input)
        self.city_input.place(relx=0.372, rely=0.285, relheight=0.057
                , relwidth=0.459)
        self.city_input.configure(takefocus="")
        self.city_input.configure(cursor="ibeam")
        self.state_input = ttk.Entry(self.top)
        create_context_menu(self.state_input)
        self.state_input.place(relx=0.372, rely=0.368, relheight=0.057
                , relwidth=0.459)
        self.state_input.configure(takefocus="")
        self.country_input = ttk.Entry(self.top)
        create_context_menu(self.country_input)
        self.country_input.place(relx=0.372, rely=0.455, relheight=0.057
                , relwidth=0.459)
        self.country_input.configure(takefocus="")
        self.country_input.configure(cursor="ibeam")
        self.priv_key_input = ttk.Entry(self.top)
        create_context_menu(self.priv_key_input)
        self.priv_key_input.place(relx=0.372, rely=0.692, relheight=0.057
                , relwidth=0.459)
        self.priv_key_input.configure(takefocus="")
        self.csr_input = ttk.Entry(self.top)
        create_context_menu(self.csr_input)
        self.csr_input.place(relx=0.372, rely=0.622, relheight=0.057
                , relwidth=0.459)
        self.csr_input.configure(takefocus="")
        self.csr_input.configure(cursor="ibeam")
        self.sans_input = ScrolledText(self.top)
        create_context_menu(self.sans_input)
        self.sans_input.place(relx=0.372, rely=0.523, relheight=0.066
                , relwidth=0.459)
        self.sans_input.configure(background="white")
        self.sans_input.configure(font="-family {Times New Roman} -size 12")
        self.sans_input.configure(foreground="black")
        self.sans_input.configure(highlightbackground="#d9d9d9")
        self.sans_input.configure(highlightcolor="black")
        self.sans_input.configure(insertbackground="black")
        self.sans_input.configure(insertborderwidth="3")
        self.sans_input.configure(selectbackground="#c4c4c4")
        self.sans_input.configure(selectforeground="black")
        self.sans_input.configure(wrap="none")

    def display(self):
        message = f"openssl req -new -newkey rsa:2048 -nodes -keyout {self.priv_key_input.get()} -subj '/C={self.country_input.get()}/ST={self.state_input.get()}/L={self.city_input.get()}/O={self.org_input.get()}/OU={self.dept_input.get()}/CN={self.common_name_input.get()}/' -addext 'subjectAltName={self.sans_input.get('1.0', 'end').strip()}' -out {self.csr_input.get()}"
        self.result.delete(0, tk.END)  # Corrected from ttk.END to tk.END
        self.result.insert(tk.END, message)  # Corrected from ttk.END to tk.END

    def copy_result(self):
        self.top.clipboard_clear()
        contents = "\n".join(self.result.get(0, tk.END))
        self.top.clipboard_append(contents) 

def open_CSRExistingKey():
    global _top08, _w08
    _top08 = tk.Toplevel(root)
    _w08 = CSRExistingKey(_top08)

class CSRExistingKey:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 406
        window_height = 279

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Create CSR from Existing Key")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top
        self.style = ttk.Style()
        
        self.csr_label = ttk.Label(self.top)
        self.csr_label.place(relx=0.165, rely=0.036, height=34, width=101)
        
        self.csr_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.csr_label.configure(relief="flat")
        self.csr_label.configure(anchor='w')
        self.csr_label.configure(justify='left')
        self.csr_label.configure(text='''CSR Name:''')
        self.csr_label.configure(compound='left')
        
        self.csr_input = ttk.Entry(self.top)
        create_context_menu(self.csr_input)
        self.csr_input.place(relx=0.443, rely=0.054, relheight=0.125
                , relwidth=0.507)
        self.csr_input.configure(takefocus="")
        self.csr_input.configure(cursor="ibeam")
        self.private_key_label = ttk.Label(self.top)
        self.private_key_label.place(relx=0.027, rely=0.275, height=34
                , width=161)
        
        self.private_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.private_key_label.configure(relief="flat")
        self.private_key_label.configure(anchor='w')
        self.private_key_label.configure(justify='left')
        self.private_key_label.configure(text='''Private Key Name:''')
        self.private_key_label.configure(compound='left')
        self.private_key_input = ttk.Entry(self.top)
        create_context_menu(self.private_key_input)
        self.private_key_input.place(relx=0.443, rely=0.287, relheight=0.125
                , relwidth=0.507)
        self.private_key_input.configure(takefocus="")
        
        self.result = ScrolledText(self.top)
        create_context_menu(self.result)
        self.result.place(relx=0.047, rely=0.591, relheight=0.165
                , relwidth=0.899)
        
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        
        
        self.result.configure(wrap="none")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.345, rely=0.466, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=self.generate)
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.345, rely=0.824, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=self.copy_to_clipboard)
        self.copy_button.configure(compound='left')

    def generate(self):
        command = f"openssl req -key {self.private_key_input.get()} -new -out {self.csr_input.get()}"
        self.result.delete(1.0, tk.END)  # Corrected from ttk.END to tk.END
        self.result.insert(tk.END, command)  # Corrected from ttk.END to tk.END

    def copy_to_clipboard(self):
        self.top.clipboard_clear()
        self.top.clipboard_append(self.result.get("1.0", tk.END).strip())

def open_CreatePFX():
    global _top09, _w09
    _top09 = tk.Toplevel(root)
    _w09 = CreatePFX(_top09)

class CreatePFX:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 427
        window_height = 290

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Create PFX Generator")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        self.private_key_label = ttk.Label(self.top)
        self.private_key_label.place(relx=0.028, rely=0.034, height=23
                , width=161)
        self.private_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.private_key_label.configure(relief="flat")
        self.private_key_label.configure(anchor='w')
        self.private_key_label.configure(justify='left')
        self.private_key_label.configure(text='''Private Key Name:''')
        self.private_key_label.configure(compound='left')
        self.private_key_input = ttk.Entry(self.top)
        create_context_menu(self.private_key_input)
        self.private_key_input.place(relx=0.422, rely=0.034, relheight=0.125
                , relwidth=0.506)
        self.private_key_input.configure(takefocus="")
        self.private_key_input.configure(cursor="ibeam")
        self.certificate_label = ttk.Label(self.top)
        self.certificate_label.place(relx=0.049, rely=0.172, height=23
                , width=151)
        self.certificate_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.certificate_label.configure(relief="flat")
        self.certificate_label.configure(anchor='w')
        self.certificate_label.configure(justify='left')
        self.certificate_label.configure(text='''Certificate Name:''')
        self.certificate_label.configure(compound='left')
        self.certificate_input = ttk.Entry(self.top)
        create_context_menu(self.certificate_input)
        self.certificate_input.place(relx=0.422, rely=0.172, relheight=0.125
                , relwidth=0.506)
        self.certificate_input.configure(takefocus="")
        self.certificate_input.configure(cursor="ibeam")
        self.pfx_label = ttk.Label(self.top)
        self.pfx_label.place(relx=0.009, rely=0.31, height=23, width=171)
        self.pfx_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.pfx_label.configure(relief="flat")
        self.pfx_label.configure(anchor='w')
        self.pfx_label.configure(justify='left')
        self.pfx_label.configure(text='''Desired PFX Name:''')
        self.pfx_label.configure(compound='left')
        self.pfx_input = ttk.Entry(self.top)
        create_context_menu(self.pfx_input)
        self.pfx_input.place(relx=0.422, rely=0.31, relheight=0.125
                , relwidth=0.506)
        self.pfx_input.configure(takefocus="")
        self.pfx_input.configure(cursor="ibeam")
        self.result = ScrolledText(self.top)
        create_context_menu(self.result)
        self.result.place(relx=0.047, rely=0.586, relheight=0.19, relwidth=0.902)

        
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(insertborderwidth="3")
        self.result.configure(wrap="none")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.351, rely=0.448, height=29, width=98)
        self.generate_button.configure(command=lambda: self.display())
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.351, rely=0.828, height=29, width=98)
        self.copy_button.configure(command=lambda: self.copy_result())
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(compound='left')
        
    def display(self):
        message = f"openssl pkcs12 -export -out {self.pfx_input.get()} -inkey {self.private_key_input.get()} -in {self.certificate_input.get()}"
        self.result.delete(1.0, tk.END)
        self.result.insert(tk.END, message)

    def copy_result(self):
        self.top.clipboard_clear()
        self.top.clipboard_append(self.result.get(1.0, tk.END))

def open_ExtractPrivateKey():
    global _top10, _w10
    _top10 = tk.Toplevel(root)
    _w10 = ExtractPrivateKey(_top10)

class ExtractPrivateKey:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 406
        window_height = 279

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Extract Private Key from PFX")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

       
        self.pfx_label = ttk.Label(self.top)
        self.pfx_label.place(relx=0.099, rely=0.036, height=34, width=141)
        self.pfx_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.pfx_label.configure(relief="flat")
        self.pfx_label.configure(anchor='w')
        self.pfx_label.configure(justify='left')
        self.pfx_label.configure(text='''PFX File Name:''')
        self.pfx_label.configure(compound='left')
        self.pfx_input = ttk.Entry(self.top)
        create_context_menu(self.pfx_input)
        self.pfx_input.place(relx=0.443, rely=0.054, relheight=0.125
                , relwidth=0.507)
        self.pfx_input.configure(takefocus="")
        self.pfx_input.configure(cursor="ibeam")
        self.private_key_label = ttk.Label(self.top)
        self.private_key_label.place(relx=0.027, rely=0.272, height=34
                , width=161)
        self.private_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.private_key_label.configure(relief="flat")
        self.private_key_label.configure(anchor='w')
        self.private_key_label.configure(justify='left')
        self.private_key_label.configure(text='''Private Key Name:''')
        self.private_key_label.configure(compound='left')
        self.private_key_input = ttk.Entry(self.top)
        create_context_menu(self.private_key_input)
        self.private_key_input.place(relx=0.443, rely=0.287, relheight=0.125
                , relwidth=0.507)
        self.private_key_input.configure(takefocus="")
        
        self.result = ScrolledText(self.top)
        create_context_menu(self.result)
        self.result.place(relx=0.047, rely=0.591, relheight=0.165
                , relwidth=0.899)
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(insertborderwidth="3")
        self.result.configure(wrap="none")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.345, rely=0.466, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=lambda: self.display())
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.345, rely=0.824, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=lambda: self.copy_result())
        self.copy_button.configure(compound='left')

    def display(self):
        message = f"openssl pkcs12 -in {self.pfx_input.get()} -nocerts -nodes -out {self.private_key_input.get()}"
        self.result.delete(1.0, tk.END)
        self.result.insert(tk.END, message)

    def copy_result(self):
        self.top.clipboard_clear()
        self.top.clipboard_append(self.result.get("1.0", tk.END))

def open_ExtractCertificate():
    global _top11, _w11
    _top11 = tk.Toplevel(root)
    _w11 = ExtractCertificate(_top11)

class ExtractCertificate:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 406
        window_height = 279

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Extract Certificate from PFX")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

       
        self.pfx_label = ttk.Label(self.top)
        self.pfx_label.place(relx=0.123, rely=0.036, height=34, width=141)
        self.pfx_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.pfx_label.configure(relief="flat")
        self.pfx_label.configure(anchor='w')
        self.pfx_label.configure(justify='left')
        self.pfx_label.configure(text='''PFX File Name:''')
        self.pfx_label.configure(compound='left')
        self.pfx_input = ttk.Entry(self.top)
        create_context_menu(self.pfx_input)
        self.pfx_input.place(relx=0.468, rely=0.054, relheight=0.125
                , relwidth=0.483)
        self.pfx_input.configure(takefocus="")
        self.pfx_input.configure(cursor="ibeam")
        self.cert_file_label = ttk.Label(self.top)
        self.cert_file_label.place(relx=0.002, rely=0.272, height=34, width=191)
        self.cert_file_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.cert_file_label.configure(relief="flat")
        self.cert_file_label.configure(anchor='w')
        self.cert_file_label.configure(justify='left')
        self.cert_file_label.configure(text='''Certificate File Name:''')
        self.cert_file_label.configure(compound='left')
        self.cert_file_input = ttk.Entry(self.top)
        create_context_menu(self.cert_file_input)
        self.cert_file_input.place(relx=0.468, rely=0.287, relheight=0.125
                , relwidth=0.483)
        self.cert_file_input.configure(takefocus="")
        
        self.result = ScrolledText(self.top)
        create_context_menu(self.result)
        self.result.place(relx=0.047, rely=0.591, relheight=0.165
                , relwidth=0.899)
        
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(foreground="black")
        self.result.configure(insertborderwidth="3")
        self.result.configure(wrap="none")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.345, rely=0.466, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=lambda :self.display())
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.345, rely=0.824, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=lambda :self.copy_result())
        self.copy_button.configure(compound='left')

    def display(self):
        message = f"openssl pkcs12 -in {self.pfx_input.get()} -clcerts -nokeys -out {self.cert_file_input.get()}"
        self.result.delete(1.0, tk.END)
        self.result.insert(tk.END, message)

    def copy_result(self):
        self.top.clipboard_clear()
        self.top.clipboard_append(self.result.get("1.0", tk.END))

def open_RemoveKeyPass():
    global _top12, _w12
    _top12 = tk.Toplevel(root)
    _w12 = RemoveKeyPass(_top12)

class RemoveKeyPass:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 406
        window_height = 279

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Remove Password from Key File")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        
        self.pass_key_file = ttk.Label(self.top)
        self.pass_key_file.place(relx=0.025, rely=0.036, height=34, width=161)
        self.pass_key_file.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.pass_key_file.configure(relief="flat")
        self.pass_key_file.configure(anchor='w')
        self.pass_key_file.configure(justify='left')
        self.pass_key_file.configure(text='''Protected Key File:''')
        self.pass_key_file.configure(compound='left')
        self.pass_key_input = ttk.Entry(self.top)
        create_context_menu(self.pass_key_input)
        self.pass_key_input.place(relx=0.443, rely=0.054, relheight=0.125
                , relwidth=0.507)
        self.pass_key_input.configure(takefocus="")
        self.pass_key_input.configure(cursor="ibeam")
        self.pass_key_input_tooltip = \
        ToolTip(self.pass_key_input, '''add .key or .pem extension''')

        self.new_key_label = ttk.Label(self.top)
        self.new_key_label.place(relx=0.123, rely=0.272, height=34, width=121)
        self.new_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.new_key_label.configure(relief="flat")
        self.new_key_label.configure(anchor='w')
        self.new_key_label.configure(justify='left')
        self.new_key_label.configure(text='''New Key File:''')
        self.new_key_label.configure(compound='left')
        self.new_key_input = ttk.Entry(self.top)
        create_context_menu(self.new_key_input)
        self.new_key_input.place(relx=0.443, rely=0.287, relheight=0.125
                , relwidth=0.507)
        self.new_key_input.configure(takefocus="")
        self.new_key_input_tooltip = \
        ToolTip(self.new_key_input, '''add .key or .pem extension''')

        self.result = ScrolledText(self.top)
        create_context_menu(self.result)
        self.result.place(relx=0.047, rely=0.591, relheight=0.165
                , relwidth=0.899)
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(insertborderwidth="3")
        self.result.configure(wrap="none")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.345, rely=0.466, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=lambda: self.display())
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.345, rely=0.824, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=lambda: self.copy_result())
        self.copy_button.configure(compound='left')
        self.pass_key_message = tk.Message(self.top)
        self.pass_key_message.place(relx=0.0, rely=0.143, relheight=0.118
                , relwidth=0.365)
        self.pass_key_message.configure(font="-family {Times New Roman} -size 11")
        self.pass_key_message.configure(padx="1")
        self.pass_key_message.configure(pady="1")
        self.pass_key_message.configure(text='''(The key file with the password)''')
        self.pass_key_message.configure(width=148)

    def display(self):
        message = f"openssl rsa -in {self.pass_key_input.get()} -out {self.new_key_input.get()}"
        self.result.delete(1.0, tk.END)
        self.result.insert(tk.END, message)

    def copy_result(self):
        self.top.clipboard_clear()
        self.top.clipboard_append(self.result.get("1.0", tk.END))

def open_ConvertKeyFile():
    global _top13, _w13
    _top13 = tk.Toplevel(root)
    _w13 = ConvertKeyFile(_top13)

class ConvertKeyFile:
    def __init__(self, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''

        main_window = top.master  # Assuming top is a child window of the main window
        window_width = 406
        window_height = 279

        main_window_x = main_window.winfo_x()
        main_window_y = main_window.winfo_y()
        main_window_width = main_window.winfo_width()

        x = main_window_x + main_window_width
        y = main_window_y

        top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        top.minsize(120, 1)
        top.maxsize(6164, 1061)
        top.resizable(False, False)
        top.title("Convert Key to RSA Key")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        icon_ico = os.path.join(script_dir, "BASK.ico")
        top.iconbitmap(icon_ico)
        self.top = top

        
        self.original_key_label = ttk.Label(self.top)
        self.original_key_label.place(relx=0.052, rely=0.036, height=34
                , width=151)
        self.original_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.original_key_label.configure(relief="flat")
        self.original_key_label.configure(anchor='w')
        self.original_key_label.configure(justify='left')
        self.original_key_label.configure(text='''Original Key File:''')
        self.original_key_label.configure(compound='left')
        self.original_key_input = ttk.Entry(self.top)
        create_context_menu(self.original_key_input)
        self.original_key_input.place(relx=0.443, rely=0.054, relheight=0.125
                , relwidth=0.507)
        self.original_key_input.configure(takefocus="")
        self.original_key_input_tooltip = \
        ToolTip(self.original_key_input, '''add .key or .pem extension''')

        self.new_key_label = ttk.Label(self.top)
        self.new_key_label.place(relx=0.025, rely=0.28, height=34, width=171)
        self.new_key_label.configure(font="-family {Times New Roman} -size 14 -weight bold")
        self.new_key_label.configure(relief="flat")
        self.new_key_label.configure(anchor='w')
        self.new_key_label.configure(justify='left')
        self.new_key_label.configure(text='''New RSA Key File:''')
        self.new_key_label.configure(compound='left')
        self.new_key_input = ttk.Entry(self.top)
        create_context_menu(self.new_key_input)
        self.new_key_input.place(relx=0.443, rely=0.287, relheight=0.125
                , relwidth=0.507)
        self.new_key_input.configure(takefocus="")
        
        self.new_key_input_tooltip = \
        ToolTip(self.new_key_input, '''add .key or .pem extension''')

        self.result = ScrolledText(self.top)
        create_context_menu(self.result)
        self.result.place(relx=0.047, rely=0.591, relheight=0.165
                , relwidth=0.899)
        self.result.configure(font="-family {Times New Roman} -size 12 -weight bold")
        self.result.configure(insertborderwidth="3")
        self.result.configure(wrap="none")
        self.generate_button = ttk.Button(self.top)
        self.generate_button.place(relx=0.345, rely=0.466, height=29, width=98)
        self.generate_button.configure(takefocus="")
        self.generate_button.configure(text='''Generate''')
        self.generate_button.configure(command=lambda: self.display())
        self.generate_button.configure(compound='left')
        self.copy_button = ttk.Button(self.top)
        self.copy_button.place(relx=0.345, rely=0.824, height=29, width=98)
        self.copy_button.configure(takefocus="")
        self.copy_button.configure(text='''Copy''')
        self.copy_button.configure(command=lambda: self.copy_result())
        self.copy_button.configure(compound='left')

    def display(self):
        message = f"openssl rsa -in {self.original_key_input.get()} -out {self.new_key_input.get()}"
        self.result.delete(1.0, tk.END)
        self.result.insert(tk.END, message)

    def copy_result(self):
        self.top.clipboard_clear()
        self.top.clipboard_append(self.result.get("1.0", tk.END))

from time import time, localtime, strftime
class ToolTip(tk.Toplevel):
    """ Provides a ToolTip widget for Tkinter. """
    def __init__(self, wdgt, msg=None, msgFunc=None, delay=0.5,
                 follow=True):
        self.wdgt = wdgt
        self.parent = self.wdgt.master
        tk.Toplevel.__init__(self, self.parent, bg='black', padx=1, pady=1)
        self.withdraw()
        self.overrideredirect(True)
        self.msgVar = tk.StringVar()
        if msg is None:
            self.msgVar.set('No message provided')
        else:
            self.msgVar.set(msg)
        self.msgFunc = msgFunc
        self.delay = delay
        self.follow = follow
        self.visible = 0
        self.lastMotion = 0
        self.msg = tk.Message(self, textvariable=self.msgVar, bg=_bgcolor,
                   fg=_fgcolor, font="-family {Times New Roman} -size 12",
                   aspect=1000)
        self.msg.grid()
        self.wdgt.bind('<Enter>', self.spawn, '+')
        self.wdgt.bind('<Leave>', self.hide, '+')
        self.wdgt.bind('<Motion>', self.move, '+')
    def spawn(self, event=None):
        self.visible = 1
        self.after(int(self.delay * 1000), self.show)
    def show(self):
        if self.visible == 1 and time() - self.lastMotion > self.delay:
            self.visible = 2
        if self.visible == 2:
            self.deiconify()
    def move(self, event):
        self.lastMotion = time()
        if self.follow is False:
            self.withdraw()
            self.visible = 1
        self.geometry('+%i+%i' % (event.x_root + 20, event.y_root - 10))
        try:
            self.msgVar.set(self.msgFunc())
        except:
            pass
        self.after(int(self.delay * 1000), self.show)
    def hide(self, event=None):
        self.visible = 0
        self.withdraw()
    def update(self, msg):
        self.msgVar.set(msg)
    def configure(self, **kwargs):
        backgroundset = False
        foregroundset = False
        # Get the current tooltip text just in case the user doesn't provide any.
        current_text = self.msgVar.get()
        # to clear the tooltip text, use the .update method
        if 'debug' in kwargs.keys():
            debug = kwargs.pop('debug', False)
            if debug:
                for key, value in kwargs.items():
                    print(f'key: {key} - value: {value}')
        if 'background' in kwargs.keys():
            background = kwargs.pop('background')
            backgroundset = True
        if 'bg' in kwargs.keys():
            background = kwargs.pop('bg')
            backgroundset = True
        if 'foreground' in kwargs.keys():
            foreground = kwargs.pop('foreground')
            foregroundset = True
        if 'fg' in kwargs.keys():
            foreground = kwargs.pop('fg')
            foregroundset = True

        fontd = kwargs.pop('font', None)
        if 'text' in kwargs.keys():
            text = kwargs.pop('text')
            if (text == '') or (text == "\n"):
                text = current_text
            else:
                self.msgVar.set(text)
        reliefd = kwargs.pop('relief', 'flat')
        justifyd = kwargs.pop('justify', 'left')
        padxd = kwargs.pop('padx', 1)
        padyd = kwargs.pop('pady', 1)
        borderwidthd = kwargs.pop('borderwidth', 2)
        wid = self.msg      # The message widget which is the actual tooltip
        if backgroundset:
            wid.config(bg=background)
        if foregroundset:
            wid.config(fg=foreground)
        wid.config(font=fontd)
        wid.config(borderwidth=borderwidthd)
        wid.config(relief=reliefd)
        wid.config(justify=justifyd)
        wid.config(padx=padxd)
        wid.config(pady=padyd)
#                   End of Class ToolTip

# The following code is added to facilitate the Scrolled widgets you specified.
class AutoScroll(object):
    '''Configure the scrollbars for a widget.'''
    def __init__(self, master):
        #  Rozen. Added the try-except clauses so that this class
        #  could be used for scrolled entry widget for which vertical
        #  scrolling is not supported. 5/7/14.
        try:
            vsb = ttk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        hsb = ttk.Scrollbar(master, orient='horizontal', command=self.xview)
        try:
            self.configure(yscrollcommand=self._autoscroll(vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(hsb))
        self.grid(column=0, row=0, sticky='nsew')
        try:
            vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        hsb.grid(column=0, row=1, sticky='ew')
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)
        # Copy geometry methods of master  (taken from ScrolledText.py)
        methods = tk.Pack.__dict__.keys() | tk.Grid.__dict__.keys() \
                  | tk.Place.__dict__.keys()
        for meth in methods:
            if meth[0] != '_' and meth not in ('config', 'configure'):
                setattr(self, meth, getattr(master, meth))

    @staticmethod
    def _autoscroll(sbar):
        '''Hide and show scrollbar as needed.'''
        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)
        return wrapped

    def __str__(self):
        return str(self.master)

def _create_container(func):
    '''Creates a ttk Frame with a given master, and use this new frame to
    place the scrollbars and the widget.'''
    def wrapped(cls, master, **kw):
        container = ttk.Frame(master)
        container.bind('<Enter>', lambda e: _bound_to_mousewheel(e, container))
        container.bind('<Leave>', lambda e: _unbound_to_mousewheel(e, container))
        return func(cls, container, **kw)
    return wrapped

class ScrolledText(AutoScroll, tk.Text):
    '''A standard Tkinter Text widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Text.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)

class ScrolledListBox(AutoScroll, tk.Listbox):
    '''A standard Tkinter Listbox widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Listbox.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)
    def size_(self):
        sz = tk.Listbox.size(self)
        return sz

class ScrolledTreeView(AutoScroll, ttk.Treeview):
    '''A standard ttk Treeview widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        ttk.Treeview.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)

import platform
def _bound_to_mousewheel(event, widget):
    child = widget.winfo_children()[0]
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        child.bind_all('<MouseWheel>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-MouseWheel>', lambda e: _on_shiftmouse(e, child))
    else:
        child.bind_all('<Button-4>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Button-5>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-Button-4>', lambda e: _on_shiftmouse(e, child))
        child.bind_all('<Shift-Button-5>', lambda e: _on_shiftmouse(e, child))

def _unbound_to_mousewheel(event, widget):
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        widget.unbind_all('<MouseWheel>')
        widget.unbind_all('<Shift-MouseWheel>')
    else:
        widget.unbind_all('<Button-4>')
        widget.unbind_all('<Button-5>')
        widget.unbind_all('<Shift-Button-4>')
        widget.unbind_all('<Shift-Button-5>')

def _on_mousewheel(event, widget):
    if platform.system() == 'Windows':
        widget.yview_scroll(-1*int(event.delta/120),'units')
    elif platform.system() == 'Darwin':
        widget.yview_scroll(-1*int(event.delta),'units')
    else:
        if event.num == 4:
            widget.yview_scroll(-1, 'units')
        elif event.num == 5:
            widget.yview_scroll(1, 'units')

def _on_shiftmouse(event, widget):
    if platform.system() == 'Windows':
        widget.xview_scroll(-1*int(event.delta/120), 'units')
    elif platform.system() == 'Darwin':
        widget.xview_scroll(-1*int(event.delta), 'units')
    else:
        if event.num == 4:
            widget.xview_scroll(-1, 'units')
        elif event.num == 5:
            widget.xview_scroll(1, 'units')

def center_window(window, width=300, height=200):
    # get screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # calculate position x and y coordinates
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    window.geometry('%dx%d+%d+%d' % (width, height, x, y))

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

    icon_ico = resource_path("BASK.ico")

# def check_license(key):
#     url = "https://api.htrconsulting.guru:8443/validate"
#     headers = {"Content-Type": "application/json"}
#     data = {"key": key}
#     response = requests.post(url, headers=headers, data=json.dumps(data))

#     if response.status_code == 200:
#         result = response.json()
#         if "success" in result:
#             print("License key is valid. Starting the main program...")
#             return True
#         elif "error" in result:
#             messagebox.showerror("Error", "License Key is invalid, please update to the latest version.")
#             return False
#     else:
#         print(f"Error: {response.status_code}")
#         return False

def start_main_window():
    global root, progress  # Add progress to global variables
    # Check the license key
    # is_valid_key = check_license("RRBO8CYY8XMITQQR")

    # if not is_valid_key:
    #     root = tk.Tk()
    #     root.withdraw()  # Hide the root window
    #     messagebox.showerror("Error", "License Key is invalid, please update to the latest version.")
    #     sys.exit()
        
    progress.stop()  # Stop the progress bar
    root.destroy()  # Destroy the loading window
    
    
    root = tk.Tk()
    root.protocol('WM_DELETE_WINDOW', root.destroy)
    
    # Set the icon for the main application
    script_dir = os.path.dirname(os.path.realpath(__file__))
    icon_ico = os.path.join(script_dir, "BASK.ico")
    root.iconbitmap(icon_ico)
    
    # Creates a toplevel widget.
    global _top1, _w1
    _top1 = root
    _w1 = Toplevel1(_top1)
    style = ttk.Style()
    style.configure('TButton', font=('Times New Roman', 10, 'bold'))
    
    root.mainloop()

def main():
    '''Main entry point for the application.'''
    global root, progress
    root = tk.Tk()
    
    script_dir = os.path.dirname(os.path.realpath(__file__))
    icon_ico = os.path.join(script_dir, "BASK.ico")
    root.iconbitmap(icon_ico) # Set the icon for the loading window
    Label(root, text='Loading and checking license...', font=('Times New Roman', 15, 'bold')).pack(pady=10)
    
    progress = ttk.Progressbar(root, length=200, mode='indeterminate')
    progress.pack(pady=5)
    progress.start()
    # Use the function
    
    root.after(2000, start_main_window)  # Start the main window after 2 seconds
    center_window(root, 300, 100)
    root.mainloop()

    

main()
