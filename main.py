import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from threading import Thread
from queue import Queue, Empty

from scanner import scan_path, mask_secret
from cli import export_csv


# ==========================================
# APPLICATION COLORS
# ==========================================

BG_COLOR = "#121B2B"
CARD_COLOR = "#1E293B"
INPUT_COLOR = "#0F172A"
BUTTON_COLOR = "#334155"
ACCENT_COLOR = "#0284C7"
GREEN_COLOR = "#16A34A"
TEXT_COLOR = "#F8FAFC"
MUTED_COLOR = "#94A3B8"
WARNING_COLOR = "#FBBF24"


# ==========================================
# APPLICATION CLASS
# ==========================================

class SecretGuardApp:

    def __init__(self, root):
        self.root = root

        root.title("SecretGuard - Security Scanner")
        root.geometry("1050x750")
        root.minsize(850, 650)
        root.configure(bg=BG_COLOR)

        self.target_path = tk.StringVar()
        self.files_count = tk.StringVar(value="0")
        self.secrets_count = tk.StringVar(value="0")
        self.status_text = tk.StringVar(
            value="Ready to scan."
        )

        self.current_findings = []
        self.scan_queue = Queue()
        self.is_scanning = False

        self.build_interface()

        self.target_path.trace_add(
            "write", self.clear_results
        )

    # ======================================
    # FILE AND FOLDER SELECTION
    # ======================================

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select a File to Scan"
        )

        if path:
            self.target_path.set(path)

    def browse_folder(self):
        path = filedialog.askdirectory(
            title="Select a Folder to Scan"
        )

        if path:
            self.target_path.set(path)

    # ======================================
    # CLEAR PREVIOUS RESULTS
    # ======================================

    def clear_results(self, *args):
        if self.is_scanning:
            return

        self.current_findings = []

        for item in self.results_table.get_children():
            self.results_table.delete(item)

        self.files_count.set("0")
        self.secrets_count.set("0")
        self.status_text.set("Ready to scan.")

        self.export_button.config(state="disabled")

    # ======================================
    # START SECURITY SCAN
    # ======================================

    def start_scan(self):
        path = self.target_path.get().strip()

        if not path:
            messagebox.showwarning(
                "Missing Path",
                "Please select a file or folder."
            )
            return

        if not Path(path).exists():
            messagebox.showerror(
                "Invalid Path",
                "The selected path does not exist."
            )
            return

        self.clear_results()

        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.file_button.config(state="disabled")
        self.folder_button.config(state="disabled")
        self.path_entry.config(state="disabled")

        self.status_text.set("Scanning files...")

        worker = Thread(
            target=self.scan_worker,
            args=(path,),
            daemon=True
        )

        worker.start()

        self.root.after(100, self.check_scan_queue)

    # ======================================
    # BACKGROUND SCANNING
    # ======================================

    def scan_worker(self, path):
        try:
            findings = scan_path(path)
            self.scan_queue.put(
                ("success", findings)
            )

        except Exception as error:
            self.scan_queue.put(
                ("error", str(error))
            )

    def check_scan_queue(self):
        try:
            result_type, data = (
                self.scan_queue.get_nowait()
            )

        except Empty:
            self.root.after(
                100, self.check_scan_queue
            )
            return

        self.is_scanning = False

        self.scan_button.config(state="normal")
        self.file_button.config(state="normal")
        self.folder_button.config(state="normal")
        self.path_entry.config(state="normal")

        if result_type == "error":
            self.status_text.set("Scan failed.")

            messagebox.showerror(
                "Scan Error", data
            )
            return

        self.display_results(data)

    # ======================================
    # DISPLAY SCAN RESULTS
    # ======================================

    def display_results(self, findings):
        self.current_findings = findings

        affected_files = set()

        for finding in findings:
            affected_files.add(
                finding["file"]
            )

            self.results_table.insert(
                "",
                "end",
                values=(
                    Path(finding["file"]).name,
                    finding["line"],
                    finding["type"],
                    mask_secret(
                        finding["match"]
                    )
                )
            )

        self.files_count.set(
            str(len(affected_files))
        )

        self.secrets_count.set(
            str(len(findings))
        )

        if findings:
            self.export_button.config(
                state="normal"
            )

            self.status_text.set(
                f"Scan complete: "
                f"{len(findings)} potential secrets."
            )

        else:
            self.status_text.set(
                "Scan complete: No patterns detected."
            )

    # ======================================
    # EXPORT CSV REPORT
    # ======================================

    def export_report(self):
        if not self.current_findings:
            messagebox.showinfo(
                "No Results",
                "There are no findings to export."
            )
            return

        output_path = filedialog.asksaveasfilename(
            title="Export Security Report",
            defaultextension=".csv",
            initialfile="SecretGuard_Report.csv",
            filetypes=[
                ("CSV Files", "*.csv")
            ]
        )

        if not output_path:
            return

        try:
            export_csv(
                self.current_findings,
                output_path
            )

            self.status_text.set(
                "Report exported successfully."
            )

            messagebox.showinfo(
                "Export Complete",
                f"Report saved to:\n{output_path}"
            )

        except OSError as error:
            messagebox.showerror(
                "Export Error", str(error)
            )

    # ======================================
    # INTERFACE CONSTRUCTION
    # ======================================

    def build_interface(self):

        # Header
        header = tk.Frame(
            self.root, bg=BG_COLOR
        )
        header.pack(
            fill="x",
            padx=30,
            pady=(25, 20)
        )

        tk.Label(
            header,
            text="SecretGuard",
            font=("Segoe UI", 26, "bold"),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Detect hardcoded secrets and protect your source code.",
            font=("Segoe UI", 11),
            fg=MUTED_COLOR,
            bg=BG_COLOR
        ).pack(anchor="w", pady=(5, 0))

        # Main container
        content = tk.Frame(
            self.root,
            bg=CARD_COLOR
        )
        content.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 15)
        )

        # Scan target label
        tk.Label(
            content,
            text="SCAN TARGET",
            font=("Segoe UI", 11, "bold"),
            fg=MUTED_COLOR,
            bg=CARD_COLOR
        ).pack(
            anchor="w",
            padx=25,
            pady=(20, 10)
        )

        # Path input
        self.path_entry = tk.Entry(
            content,
            textvariable=self.target_path,
            font=("Segoe UI", 11),
            bg=INPUT_COLOR,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR,
            relief="flat"
        )
        self.path_entry.pack(
            fill="x", padx=25, ipady=12
        )

        # Browse buttons
        buttons = tk.Frame(
            content, bg=CARD_COLOR
        )
        buttons.pack(
            fill="x",
            padx=25,
            pady=15
        )

        self.file_button = tk.Button(
            buttons,
            text="Browse File",
            command=self.browse_file,
            bg=BUTTON_COLOR,
            fg="white",
            font=("Segoe UI", 11),
            relief="flat",
            cursor="hand2"
        )
        self.file_button.pack(
            side="left",
            padx=(0, 10),
            ipadx=20,
            ipady=10
        )

        self.folder_button = tk.Button(
            buttons,
            text="Browse Folder",
            command=self.browse_folder,
            bg=BUTTON_COLOR,
            fg="white",
            font=("Segoe UI", 11),
            relief="flat",
            cursor="hand2"
        )
        self.folder_button.pack(
            side="left",
            ipadx=20,
            ipady=10
        )

        # Start Scan button
        self.scan_button = tk.Button(
            content,
            text="START SECURITY SCAN",
            command=self.start_scan,
            bg=ACCENT_COLOR,
            fg="white",
            activebackground="#0369A1",
            activeforeground="white",
            font=("Segoe UI", 12, "bold"),
            relief="flat",
            cursor="hand2"
        )
        self.scan_button.pack(
            fill="x",
            padx=25,
            pady=(0, 10),
            ipady=12
        )

        # Export button
        self.export_button = tk.Button(
            content,
            text="EXPORT SCAN REPORT",
            command=self.export_report,
            bg=GREEN_COLOR,
            fg="white",
            disabledforeground=MUTED_COLOR,
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            cursor="hand2",
            state="disabled"
        )
        self.export_button.pack(
            fill="x",
            padx=25,
            pady=(0, 20),
            ipady=10
        )

        # Dashboard
        dashboard = tk.Frame(
            content, bg=CARD_COLOR
        )
        dashboard.pack(
            fill="x",
            padx=25,
            pady=(0, 20)
        )

        self.create_stat_card(
            dashboard,
            "FILES WITH FINDINGS",
            self.files_count,
            TEXT_COLOR
        )

        self.create_stat_card(
            dashboard,
            "POTENTIAL SECRETS",
            self.secrets_count,
            WARNING_COLOR
        )

        # Results heading
        tk.Label(
            content,
            text="SCAN RESULTS",
            font=("Segoe UI", 11, "bold"),
            fg=MUTED_COLOR,
            bg=CARD_COLOR
        ).pack(
            anchor="w",
            padx=25,
            pady=(0, 10)
        )

        # Results table styling
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background=INPUT_COLOR,
            foreground=TEXT_COLOR,
            fieldbackground=INPUT_COLOR,
            rowheight=30,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=BUTTON_COLOR,
            foreground=TEXT_COLOR,
            font=("Segoe UI", 10, "bold")
        )

        style.map(
            "Treeview",
            background=[
                ("selected", ACCENT_COLOR)
            ],
            foreground=[
                ("selected", "white")
            ]
        )

        table_frame = tk.Frame(
            content, bg=CARD_COLOR
        )
        table_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 15)
        )

        columns = (
            "File", "Line", "Type", "Match"
        )

        self.results_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        widths = {
            "File": 200,
            "Line": 70,
            "Type": 160,
            "Match": 350
        }

        for column in columns:
            self.results_table.heading(
                column, text=column
            )
            self.results_table.column(
                column,
                width=widths[column],
                minwidth=60,
                anchor=(
                    "center"
                    if column == "Line"
                    else "w"
                )
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.results_table.yview
        )

        self.results_table.configure(
            yscrollcommand=scrollbar.set
        )

        scrollbar.pack(
            side="right", fill="y"
        )

        self.results_table.pack(
            side="left",
            fill="both",
            expand=True
        )

        # Status bar
        tk.Label(
            self.root,
            textvariable=self.status_text,
            font=("Segoe UI", 10),
            fg=MUTED_COLOR,
            bg=BG_COLOR,
            anchor="w"
        ).pack(
            fill="x",
            padx=30,
            pady=(0, 15)
        )

    # ======================================
    # DASHBOARD CARD HELPER
    # ======================================

    def create_stat_card(
        self, parent, label, variable, color
    ):
        card = tk.Frame(
            parent, bg=INPUT_COLOR
        )
        card.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 10)
        )

        tk.Label(
            card,
            text=label,
            font=("Segoe UI", 10, "bold"),
            fg=MUTED_COLOR,
            bg=INPUT_COLOR
        ).pack(pady=(12, 5))

        tk.Label(
            card,
            textvariable=variable,
            font=("Segoe UI", 24, "bold"),
            fg=color,
            bg=INPUT_COLOR
        ).pack(pady=(0, 12))


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":
    root = tk.Tk()
    app = SecretGuardApp(root)
    root.mainloop()
