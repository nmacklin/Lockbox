import os
import tkinter as tk
from tkinter import ttk
from tkinter import W


class StartupFrame:
    def __init__(self, mainframe, select_dir, create_dir):
        self.start_frame = ttk.Frame(mainframe)
        self.start_frame.grid()

        ttk.Button(self.start_frame, text="Select encrypted directory", width=44,
                   command=lambda: select_dir(self.start_frame, None)).grid(column=0, row=0)
        ttk.Button(self.start_frame, text="Create encrypted directory", width=44,
                   command=lambda: create_dir(self.start_frame)).grid(column=1, row=0)

        for child in self.start_frame.winfo_children():
            child.grid_configure(padx=15, pady=25)


class EnterPassFrame:
    def __init__(self, mainframe, vault_dir, check_password):
        self.pass_frame = ttk.Frame(mainframe)
        self.pass_frame.grid()

        self.label = ttk.Label(self.pass_frame, text="Please enter password")
        self.label.grid()

        self.password = tk.StringVar()
        self.pass_entry = ttk.Entry(self.pass_frame, width=40, textvariable=self.password)
        self.pass_entry.bind('<Return>',
                             lambda x: check_password(vault_dir, self.password.get(), self.pass_frame))
        self.pass_entry.grid(row=1, padx=10, pady=10)
        self.pass_entry.focus_set()

        self.btn = ttk.Button(self.pass_frame, text="Submit password",
                              command=lambda: check_password(vault_dir, self.password.get(), self.pass_frame))
        self.btn.grid(row=2)


class CreatePassFrame:
    def __init__(self, mainframe, vault_dir, p_key, create_password):
        self.mainframe = mainframe
        self.pass_frame = ttk.Frame(mainframe)

        self.pass_label = ttk.Label(self.pass_frame, text="Please enter and confirm new password")

        self.password = tk.StringVar()
        self.password_2 = tk.StringVar()

        self.pass_entry = ttk.Entry(self.pass_frame, width=40, textvariable=self.password)
        self.confirm_entry = ttk.Entry(self.pass_frame, width=40, textvariable=self.password_2)
        self.confirm_entry.bind('<Return>', lambda x: create_password(self.password.get(), self.password_2.get(),
                                                                      self, vault_dir))

        self.pass_button = ttk.Button(self.pass_frame, text="Submit Password",
                                      command=lambda: create_password(self.password.get(), self.password_2.get(),
                                                                      self, vault_dir))

        self.pass_frame.grid()
        self.pass_label.grid(pady=(15, 0))
        self.pass_entry.grid(row=1, padx=20, pady=(5, 5))
        self.confirm_entry.grid(row=2, padx=20, pady=(5, 15))
        self.pass_entry.focus_set()
        self.pass_button.grid(row=3)

        self.p_key = p_key  # Old plain key passed to create_password function for changing passphrase


class AccessPanel:
    """ Dynamically unpacks core_functions
     @DynamicAttrs
    """

    def __init__(self, mainframe, keychain, core_functions):
        self.access_frame = ttk.Frame(mainframe)
        self.access_frame.grid()

        self.label = ttk.Label(self.access_frame, text=keychain['vault_dir'])
        self.label.grid()

        for (name, core_function) in core_functions.items():
            setattr(self, name, core_function)

        self.open_file_btn = ttk.Button(self.access_frame, text="View encrypted file",
                                        command=lambda: self.view_file(keychain), width=30)
        self.edit_file_btn = ttk.Button(self.access_frame, text="Edit encrypted file",
                                        command=lambda: self.edit_file(keychain), width=30)
        self.import_file_btn = ttk.Button(self.access_frame, text="Import and encrypt file",
                                          command=lambda: self.import_file(keychain), width=30)
        self.import_folder_btn = ttk.Button(self.access_frame, text="Import and encrypt folder",
                                            command=lambda: self.import_folder(keychain), width=30)
        self.export_file_btn = ttk.Button(self.access_frame, text="Export and decrypt file",
                                          command=lambda: self.export_file(keychain), width=30)
        self.export_folder_btn = ttk.Button(self.access_frame, text="Export and decrypt folder",
                                            command=lambda: self.export_folder(keychain), width=30)
        self.change_passphrase_btn = ttk.Button(self.access_frame, text="Change passphrase", width=30,
                                                command=lambda: self.change_passphrase(keychain, self.access_frame))

        self.open_file_btn.grid(row=1, pady=10, padx=20, sticky=W)
        self.edit_file_btn.grid(row=2, pady=10, padx=20, sticky=W)
        self.import_file_btn.grid(row=3, pady=10, padx=20, sticky=W)
        self.import_folder_btn.grid(row=4, pady=10, padx=20, sticky=W)
        self.export_file_btn.grid(row=5, pady=10, padx=20, sticky=W)
        self.export_folder_btn.grid(row=6, pady=10, padx=20, sticky=W)
        self.change_passphrase_btn.grid(row=7, pady=10, padx=20, sticky=W)


class EditFileSentinel:
    # Creates pop-up that stays open for the duration of file edit
    # Its closure triggers event to save changes
    def __init__(self, top, filename, temp_filename, keychain, sentinel_close):
        self.top = top

        self.basename = os.path.basename(filename)[:-7]
        self.message = ttk.Label(top, text="Please leave window open until you have finished editing and "
                                           "closed the open file:\n" + self.basename)

        self.close_btn = ttk.Button(top, text="Finished editing",
                                    command=lambda: sentinel_close(filename, temp_filename, keychain, top))

        self.message.grid(row=0, pady=5, padx=15)
        self.close_btn.grid(row=1, pady=5)
