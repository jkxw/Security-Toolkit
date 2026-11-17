"""
Security Toolkit - أداة أمان للويندوز
المتطلبات:  Python 3.9+  و  pip install psutil
التشغيل:    python security_toolkit.py   (يفضل كمسؤول Administrator)
"""
import ctypes
import hashlib
import os
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk, filedialog, messagebox

try:
    import psutil
except ImportError:
    print("ثبّت المكتبة أولاً:  pip install psutil")
    sys.exit(1)

try:
    import winreg
except ImportError:
    print("هذه الأداة تعمل على ويندوز فقط.")
    sys.exit(1)

NO_WINDOW = 0x08000000
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 5555, 9001, 12345, 6666}
SUSPICIOUS_PATHS = (
    "\\temp\\",
    "\\downloads\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ps(cmd, timeout=60):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=NO_WINDOW,
        )
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"ERROR: {e}"


def reg_read(hive, path, name):
    try:
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


# ───────────────────────── مراقب الشبكة ─────────────────────────
class NetworkTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.alerted = set()
        self.auto = tk.BooleanVar(value=True)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(bar, text="تحديث", command=self.refresh).pack(side="right")
        ttk.Checkbutton(bar, text="تحديث تلقائي كل 5 ثواني", variable=self.auto).pack(side="right", padx=10)
        ttk.Button(bar, text="إنهاء البرنامج المحدد", command=self.kill_selected).pack(side="right", padx=5)
        self.count = ttk.Label(bar, text="")
        self.count.pack(side="left")

        cols = ("process", "pid", "local", "remote", "status", "flag")
        names = ("البرنامج", "PID", "المحلي", "البعيد", "الحالة", "تنبيه")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=18)
        for c, n, w in zip(cols, names, (150, 60, 160, 180, 100, 180)):
            self.tree.heading(c, text=n)
            self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure("bad", background="#ffd6d6")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.refresh()
        self.after(5000, self.tick)

    def tick(self):
        if self.auto.get():
            self.refresh()
        self.after(5000, self.tick)

    def kill_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("تنبيه", "اختر اتصالاً من القائمة أولاً.")
            return
        item = self.tree.item(sel[0])["values"]
        name, pid = item[0], item[1]
        if not pid:
            return
        if messagebox.askyesno("تأكيد", f"هل تريد إغلاق البرنامج ({name}) ذو المعرف PID: {pid}؟"):
            try:
                psutil.Process(int(pid)).terminate()
                self.refresh()
            except Exception as e:
                messagebox.showerror("خطأ", f"تعذر إنهاء العملية: {e}")

    def refresh(self):
        rows = []
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.count.config(text="شغّل الأداة كمسؤول لعرض كل الاتصالات")
            return

        for c in conns:
            if c.status not in ("ESTABLISHED", "SYN_SENT", "LISTEN"):
                continue
            name, exe = "?", ""
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    name, exe = p.name(), (p.exe() or "")
                except Exception:
                    pass
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            flags = []
            if exe and any(s in exe.lower() for s in SUSPICIOUS_PATHS):
                flags.append("يعمل من مسار مشبوه")
            if c.raddr and c.raddr.port in SUSPICIOUS_PORTS:
                flags.append("منفذ مشبوه")
            if c.status == "LISTEN" and c.laddr and c.laddr.ip in ("0.0.0.0", "::") and flags:
                flags.append("يستمع للشبكة")
            rows.append((name, c.pid or "", local, remote, c.status, "، ".join(flags)))

        rows.sort(key=lambda r: (r[5] == "", r[0].lower()))
        self.tree.delete(*self.tree.get_children())
        suspicious_count = 0
        for r in rows:
            self.tree.insert("", "end", values=r, tags=("bad",) if r[5] else ())
            if r[5]:
                suspicious_count += 1
                key = (r[0], r[3])
                if key not in self.alerted:
                    self.alerted.add(key)

        self.count.config(text=f"إجمالي الاتصالات: {len(rows)}  |  تنبيهات مشبوهة: {suspicious_count}")


# ───────────────────────── فحص بصمة الملفات ─────────────────────────
class FileHashTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="اختر ملفاً لحساب بصمته الرقمية (SHA-256 / MD5) والتحقق من سلامته:", font=("Segoe UI", 10, "bold")).pack(anchor="e", pady=(0, 10))
        ttk.Button(frame, text="اختيار ملف للفحص...", command=self.pick_file).pack(anchor="e", pady=(0, 15))

        self.result_box = tk.Text(frame, height=12, font=("Consolas", 10), state="disabled", bg="#f4f4f4")
        self.result_box.pack(fill="both", expand=True)

    def pick_file(self):
        path = filedialog.askopenfilename(title="اختر ملفاً")
        if not path:
            return
        self.write_output("جاري حساب البصمة الرقمية للملف...")
        threading.Thread(target=self.compute_hash, args=(path,), daemon=True).start()

    def compute_hash(self, path):
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
                    md5.update(chunk)
            text = (
                f"اسم الملف : {os.path.basename(path)}\n"
                f"المسار    : {path}\n"
                f"الحجم     : {size:,} بايت\n"
                f"تاريخ التعديل: {datetime.fromtimestamp(os.path.getmtime(path))}\n"
                f"{'-'*55}\n"
                f"SHA-256   : {sha256.hexdigest()}\n"
                f"MD5       : {md5.hexdigest()}\n"
            )
        except Exception as e:
            text = f"حدث خطأ أثناء قراءة الملف: {e}"
        self.after(0, lambda: self.write_output(text))

    def write_output(self, text):
        self.result_box.config(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        self.result_box.config(state="disabled")


# ───────────────────────── فحص أمان النظام ─────────────────────────
class SystemAuditTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Button(frame, text="فحص إعدادات الحماية في ويندوز", command=self.run_audit).pack(anchor="e", pady=(0, 10))
        self.info_box = tk.Text(frame, height=15, font=("Segoe UI", 10), state="disabled", bg="#f4f4f4")
        self.info_box.pack(fill="both", expand=True)

    def run_audit(self):
        uac = reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        uac_status = "مفعّل (آمن)" if uac == 1 else "معطّل (خطر)"
        defender = ps("(Get-MpComputerStatus).RealTimeProtectionEnabled")
        def_status = "مفعّلة" if "True" in defender else f"غير مؤكدة / معطلة ({defender})"

        report = (
            f"صلاحيات المسؤول (Admin) : {'نعم' if is_admin() else 'لا (يفضل التشغيل كمسؤول)'}\n"
            f"التحكم بحساب المستخدم (UAC): {uac_status}\n"
            f"حماية Windows Defender   : {def_status}\n"
            f"وقت الفحص                : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        self.info_box.config(state="normal")
        self.info_box.delete("1.0", "end")
        self.info_box.insert("1.0", report)
        self.info_box.config(state="disabled")


# ───────────────────────── النافذة الرئيسية ─────────────────────────
def main():
    root = tk.Tk()
    admin_tag = " [مسؤول]" if is_admin() else " [مستخدم عادي]"
    root.title(f"Security Toolkit - أداة الأمان{admin_tag}")
    root.geometry("860x500")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=6, pady=6)

    notebook.add(NetworkTab(notebook), text="مراقب الشبكة والاتصالات")
    notebook.add(FileHashTab(notebook), text="فحص بصمة الملفات")
    notebook.add(SystemAuditTab(notebook), text="فحص أمان النظام")

    root.mainloop()


if __name__ == "__main__":
    main()
