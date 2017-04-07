import tkinter as tk
from tkinter import ttk
from frames import StartupFrame
from functions import cleanup_temp, select_dir, create_dir


root = tk.Tk()
root.title('Lockbox v0.2')

mainframe = ttk.Frame(root, padding='3 3 12 12')
mainframe.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S))
mainframe.columnconfigure(0, weight=1)
mainframe.rowconfigure(0, weight=1)

StartupFrame(mainframe, select_dir, create_dir)

root.protocol("WM_DELETE_WINDOW", lambda: cleanup_temp(root))
root.mainloop()
