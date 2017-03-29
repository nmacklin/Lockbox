import os
import pickle
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import random
from tempfile import mkdtemp
from shutil import rmtree
from frames import CreatePassFrame, EnterPassFrame, AccessPanel, EditFileSentinel

# Global temporary directory to be used for all file I/O
# Deleted upon closing of program in GUI.py
temp_file_dir = mkdtemp()


def select_dir(old_frame, vault_dir):
    if not vault_dir:  # Interrupts if attempting to open folder that has not been primed from encryption
        vault_dir = filedialog.askdirectory()
        if not os.path.isfile(os.path.join(vault_dir, 'cupboard.lbf')) or not vault_dir:
            messagebox.showinfo(message="Selected drive does not contain encryption data")
            return
    else:
        messagebox.showinfo(message='Success! You will now be asked to sign in with new passphrase.')

    mainframe = old_frame.master
    old_frame.destroy()

    EnterPassFrame(mainframe, vault_dir, check_password)


def check_password(vault_dir, passphrase, check_pass_frame):
    with open(os.path.join(vault_dir, "cupboard.lbf"), 'rb') as cupboard_f:
        cupboard = pickle.load(cupboard_f)
    password_bytes = passphrase[:32].encode('utf-8')
    salted_pp = password_bytes + cupboard['pp_salt']
    hashed_pw = SHA256.new(salted_pp).digest()
    if hashed_pw != cupboard['hashed_pp']:
        messagebox.showwarning(message="Submitted password does not match password on file.")
        return False
    else:
        messagebox.showinfo(message="Password accepted. Granting access.")
        access_directory(vault_dir, passphrase, check_pass_frame)


def access_directory(vault_dir, passphrase, check_pass_frame):
    with open(os.path.join(vault_dir, 'cupboard.lbf'), 'rb') as cupboard_f:
        cupboard = pickle.load(cupboard_f)
    p_key = get_key(cupboard, passphrase)

    with open(os.path.join(vault_dir, 'directory.lbf'), 'rb') as iv_f:
        iv_dir = pickle.load(iv_f)

    keychain = {
        'p_key': p_key,
        'iv_dir': iv_dir,
        'vault_dir': vault_dir
        }

    cleanup_iv_dir(keychain)

    mainframe = check_pass_frame.master
    check_pass_frame.destroy()

    core_functions = {
        'view_file': view_file,
        'edit_file': edit_file,
        'import_file': import_file,
        'import_folder': import_folder,
        'export_file': export_file,
        'export_folder': export_folder,
        'change_passphrase': change_passphrase
        }

    AccessPanel(mainframe, keychain, core_functions)


def create_dir(old_frame):
    vault_dir = filedialog.askdirectory()
    if not vault_dir:
        return
    if os.path.isfile(os.path.join(vault_dir, 'cupboard.lbf')):
        top = tk.Toplevel()
        l = ttk.Label(top, foreground='red', text="Directory already contains encryption data.")
        l.grid(pady=20, padx=20)
        return

    mainframe = old_frame.master
    old_frame.destroy()

    CreatePassFrame(mainframe, vault_dir, None, create_password)


def create_password(password, password_2, create_pass_frame, vault_dir):
    pass_frame = create_pass_frame.pass_frame

    if password != password_2:
        mismatch_label = ttk.Label(pass_frame, text="Passwords do not match", foreground="red")
        mismatch_label.grid(row=4)
        return
    if len(password) < 32:
        mismatch_label = ttk.Label(pass_frame, text="Password must be at least 32 characters", foreground="red")
        mismatch_label.grid(row=4)
        return

    with open(os.path.join(vault_dir, "cupboard.lbf"), 'wb+') as cupboard_out:
        cupboard = {}

        passphrase_bytes = password[:32].encode('utf-8')
        pp_salt = os.urandom(32)
        salted_pp = passphrase_bytes + pp_salt
        cupboard['pp_salt'] = pp_salt
        cupboard['hashed_pp'] = SHA256.new(salted_pp).digest()

        dk_salt = os.urandom(32)
        derived_key = PBKDF2(password, dk_salt, dkLen=32, count=10000)
        cupboard["dk_salt"] = dk_salt

        if create_pass_frame.p_key:  # If changing existing passphrase
            plain_rk = create_pass_frame.p_key
            cupboard_out.truncate(0)
        else:
            plain_rk = os.urandom(32)

        iv = os.urandom(16)
        cipher = AES.new(derived_key, AES.MODE_CFB, iv)
        cipher_rk = cipher.encrypt(plain_rk)
        cupboard['cipher_key'] = cipher_rk
        cupboard['rk_IV'] = iv

        pickle.dump(cupboard, cupboard_out)

    try:
        with open(os.path.join(vault_dir, "directory.lbf"), 'xb+') as f_iv_dir:
            iv_dir = {}
            pickle.dump(iv_dir, f_iv_dir)
    except FileExistsError:
        pass

    select_dir(pass_frame, vault_dir)


def open_file(keychain, filename):
    iv_dir = keychain['iv_dir']
    p_key = keychain['p_key']

    iv = iv_dir[filename[-7:]]
    cipher = AES.new(p_key, AES.MODE_CFB, iv)
    with open(filename, 'rb') as f_in:
        cipher_bytes = f_in.read()
        plain_bytes = cipher.decrypt(cipher_bytes)
        # Name joins temp dir with basename except IV id suffix
        temp_filename = os.path.join(temp_file_dir, os.path.basename(filename)[:-7])
        with open(temp_filename, 'wb') as f_out:
            f_out.write(plain_bytes)
        if sys.platform == 'win32':
            subprocess.run('start "" "' + temp_filename + '"', shell=True)
        else:
            subprocess.run('open "' + temp_filename + '"', shell=True)
    return temp_filename


def view_file(keychain):
    filenames = filedialog.askopenfilenames(initialdir=keychain['vault_dir'])
    if len(filenames) == 0:
        return
    for filename in filenames:
        open_file(keychain, filename)


def edit_file(keychain):
    filename = filedialog.askopenfilename(initialdir=keychain['vault_dir'])
    if not filename:
        return
    temp_filename = open_file(keychain, filename)
    top = tk.Toplevel()
    top.protocol("WM_DELETE_WINDOW", lambda: sentinel_close(filename, temp_filename, keychain, top))

    EditFileSentinel(top, filename, temp_filename, keychain, sentinel_close)


def overwrite_file(filename, temp_filename, keychain):
    try:
        encrypt_write_file(keychain, temp_filename, filename[:-7])  # Remove IV-ID from old filename
    except Exception as e:
        messagebox.showerror(message="File save failed. Please try again.\n\n" + str(e))
        return False
    else:
        # Remove old file and remove old IV from directory
        os.remove(filename)
        del keychain['iv_dir'][filename[-7:]]
        update_iv_dir(keychain)
        return True


def import_file(keychain):
    filenames = filedialog.askopenfilenames(title="Select file(s) to import")
    if len(filenames) == 0:
        return

    target_dir = filedialog.askdirectory(title="Select destination folder", initialdir=keychain['vault_dir'])
    if not target_dir:
        return

    for filename in filenames:
        basename = os.path.basename(filename)
        local_filename = os.path.join(target_dir, basename)

        # Check for existing file and truncate if elects to overwrite
        for (root, dirnames, f_names) in os.walk(target_dir):
            for name in f_names:
                if basename == name[:-7]:
                    if not messagebox.askokcancel(title='Overwrite?',
                                                  message="File " + local_filename + " already exists. Overwrite?"):
                        return
                    else:
                        with open(os.path.join(target_dir, basename), 'wb') as f_overwrite:
                            f_overwrite.truncate(0)
            break

        encrypt_write_file(keychain, filename, local_filename)
    messagebox.showinfo(message="Import and encryption complete for {} file(s)".format(len(filenames)))


def import_folder(keychain):
    source_dir = filedialog.askdirectory(title="Choose folder to import")
    if not source_dir:
        return

    target_dir = filedialog.askdirectory(title="Choose where to import files", initialdir=keychain['vault_dir'])
    if not target_dir:
        return

    move_folders(keychain, source_dir, target_dir, encrypt=True)
    messagebox.showinfo(message='Import successful')


def export_file(keychain):
    source_filenames = filedialog.askopenfilenames(title="Select file(s) to export", initialdir=keychain['vault_dir'])
    if not source_filenames:
        return

    target_dir = filedialog.askdirectory(title="Select location to export file")
    if not target_dir:
        return

    for source_filename in source_filenames:
        target_filename = os.path.join(target_dir, os.path.basename(source_filename))[:-7]
        decrypt_write_file(keychain, source_filename, target_filename)
    messagebox.showinfo(message='Export successful for {} file(s)'.format(len(source_filenames)))


def export_folder(keychain):
    source_dir = filedialog.askdirectory(title='Select folder to export', initialdir=keychain['vault_dir'])
    if not source_dir:
        return

    target_dir = filedialog.askdirectory(title='Select location to send files')
    if not target_dir:
        return

    move_folders(keychain, source_dir, target_dir, encrypt=False)
    messagebox.showinfo(message='Export successful')


def change_passphrase(keychain, access_frame):
    mainframe = access_frame.master
    access_frame.destroy()
    CreatePassFrame(mainframe, keychain['vault_dir'], keychain['p_key'], create_password)


def get_key(cupboard, passphrase):
    derived_key = PBKDF2(passphrase, cupboard['dk_salt'], dkLen=32, count=10000)

    cipher = AES.new(derived_key, AES.MODE_CFB, cupboard['rk_IV'])
    random_key = cipher.decrypt(cupboard['cipher_key'])
    return random_key


def sentinel_close(filename, temp_filename, keychain, top):
    success = overwrite_file(filename, temp_filename, keychain)
    messagebox.showinfo(message='Editing saved successfully')
    if success:
        top.destroy()
    else:
        return


def encrypt_write_file(keychain, filename, target_filename):
    iv_dir = keychain['iv_dir']
    p_key = keychain['p_key']

    # Generate unique, random, 7 integer identifier to serve as IV dict key
    while True:
        iv_key = str(random.randint(1000000, 9999999))
        if iv_key not in iv_dir:
            break
    iv = os.urandom(16)
    iv_dir[iv_key] = iv

    cipher = AES.new(p_key, AES.MODE_CFB, iv)
    with open(filename, 'rb') as f_in:
        plain_bytes = f_in.read()
        cipher_bytes = cipher.encrypt(plain_bytes)
    # Save file name in format filename.type1234567
    with open(target_filename + iv_key, 'wb') as f_out:
        f_out.write(cipher_bytes)
    update_iv_dir(keychain)


def move_folders(keychain, source_dir, target_dir, encrypt):
    root_dir = None
    copy_added = 0
    for (root, dir_names, filenames) in os.walk(source_dir):
        if not root_dir:
            # Create new directory in target folder
            # e.g source folder: C:\Users\Me\source, target: H:\Docs -> root: H:\Docs\source
            root_dir = os.path.join(target_dir, os.path.basename(root))
            while True:
                try:
                    os.mkdir(root_dir)
                except FileExistsError:
                    root_dir += '(Copy)'
                    copy_added += 1
                else:
                    break
            target_subdir = root_dir
        else:
            # Convoluted function to dynamically obtain paths for subdirectories in new folder
            # e.g. C:\Users\Me\Dir\Subdir -> H:\Lockbox\Dir\Subdir
            last_base = root
            last_tail = ""
            current_tail = ""
            last_tail_check = ""
            while last_tail_check != os.path.basename(root_dir):
                current_tail = os.path.join(last_tail, current_tail)
                (base, tail) = os.path.split(last_base)
                last_base = base
                last_tail = tail
                last_tail_check = last_tail + '(Copy)' * copy_added
            target_subdir = os.path.join(root_dir, current_tail)

        for dir_name in dir_names:
            os.mkdir(os.path.join(target_subdir, dir_name))
        for filename in filenames:
            filename = os.path.join(root, filename)
            target_filename = os.path.join(target_subdir, os.path.basename(filename))
            if encrypt:
                encrypt_write_file(keychain, filename, target_filename)
            else:
                target_filename = target_filename[:-7]
                decrypt_write_file(keychain, filename, target_filename)


def update_iv_dir(keychain):
    # Truncate and update IV directory file
    with open(os.path.join(keychain['vault_dir'], 'directory.lbf'), 'wb') as iv_dir_f:
        iv_dir_f.truncate(0)
        pickle.dump(keychain['iv_dir'], iv_dir_f)


def decrypt_write_file(keychain, source_filename, target_filename):
    iv = keychain['iv_dir'][source_filename[-7:]]
    cipher = AES.new(keychain['p_key'], AES.MODE_CFB, iv)
    with open(source_filename, 'rb') as f_in:
        cipher_bytes = f_in.read()
    plain_bytes = cipher.decrypt(cipher_bytes)

    while True:
        try:
            with open(target_filename, 'xb+') as f_out:
                f_out.write(plain_bytes)
        except FileExistsError:
            (name_root, ext) = os.path.splitext(target_filename)
            name_root += ' (copy)'
            target_filename = name_root + ext
        else:
            break


def cleanup_iv_dir(keychain):
    """
    Indexes all IV IDs on existing files in Lockbox and then checks each IV ID in directory.lbf to find any unnecessary
    entries
    """
    current_iv_ids = []

    for (root, dir_names, filenames) in os.walk(keychain['vault_dir']):
        for filename in filenames:
            iv_id = filename[-7:]
            if iv_id.isdigit():
                current_iv_ids.append(iv_id)

    temp_iv_dir = {}
    iv_dir = keychain['iv_dir']
    for iv_id in iv_dir:
        if iv_id in current_iv_ids:
            temp_iv_dir[iv_id] = iv_dir[iv_id]
    keychain['iv_dir'] = temp_iv_dir
    update_iv_dir(keychain)


def cleanup_temp(root):
    """
    Temporary directory is created to write deciphered bytes to file so system dialog can open the file with appropriate
    default program. Function deletes directory upon closing program.
    """
    success = False
    while not success:
        try:
            rmtree(temp_file_dir)
        except PermissionError:
            messagebox.showerror(message="Encrypted file(s) open. Please exit all encrypted file(s) before "
                                         "closing program.")
        else:
            success = True
            root.destroy()
