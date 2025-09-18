import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import logging
import sys
import os
import platform # <-- تمت إضافة هذا السطر لإصلاح الخطأ

# استيراد الوحدات التي تحتوي على منطق الفحص
try:
    from host_analyzer import (run_security_audit, scan_for_viruses, clean_junk_files, 
                               list_installed_packages, deep_uninstall_package)
except ImportError as e:
    messagebox.showerror("خطأ في الاستيراد", f"لا يمكن العثور على ملف 'host_analyzer.py'.\n{e}")
    sys.exit(1)


# --- إعداد الواجهة الرسومية ---

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Vanguard Security Scanner")
        self.geometry("900x600")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar_frame = ttk.Frame(self, width=200)
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.main_frame = ttk.Frame(self)
        self.main_frame.grid(row=0, column=1, sticky="nswe")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.log_display = scrolledtext.ScrolledText(self.main_frame, state='disabled', bg='black', fg='lime green', font=("Consolas", 10))
        self.log_display.grid(row=0, column=0, sticky="nswe")

        self.create_sidebar_buttons()

        self.log_handler = TextHandler(self.log_display)
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s', handlers=[self.log_handler])

        logging.info("تم تشغيل Vanguard Scanner. جاهز لتلقي الأوامر.")

    def create_sidebar_buttons(self):
        """إنشاء جميع الأزرار في الشريط الجانبي."""
        buttons = {
            "تدقيق أمني شامل": self.run_audit,
            "فحص الفيروسات": self.run_virus_scan,
            "تنظيف الملفات الزائدة": self.run_junk_clean,
            "إزالة برنامج": self.run_uninstall,
            "مسح النتائج": self.clear_log
        }
        
        for i, (text, command) in enumerate(buttons.items()):
            button = ttk.Button(self.sidebar_frame, text=text, command=command)
            button.grid(row=i, column=0, padx=10, pady=10, sticky="ew")

        exit_button = ttk.Button(self.sidebar_frame, text="خروج", command=self.quit)
        exit_button.grid(row=6, column=0, padx=10, pady=10, sticky="ews")

    def run_in_thread(self, target_func, *args):
        """تشغيل أي دالة في خيط منفصل لمنع تجميد الواجهة."""
        thread = threading.Thread(target=target_func, args=args)
        thread.daemon = True
        thread.start()

    def run_audit(self):
        logging.info("==============================================")
        self.run_in_thread(run_security_audit)

    def run_virus_scan(self):
        path = filedialog.askdirectory(title="اختر المجلد المراد فحصه")
        if path:
            logging.info("==============================================")
            self.run_in_thread(scan_for_viruses, path, "virus_signatures.txt", "./quarantine")

    def run_junk_clean(self):
        logging.info("==============================================")
        logging.info("سيتم طلب تأكيد حذف الملفات الزائدة في الطرفية (Terminal).")
        self.run_in_thread(clean_junk_files, "junk_rules.txt")
            
    def run_uninstall(self):
        messagebox.showinfo("معلومة", "لإزالة برنامج، يرجى استخدام سطر الأوامر حاليًا:\nsudo python main.py host --action uninstall --package <اسم_الحزمة>")

    def clear_log(self):
        """مسح محتوى نافذة النتائج."""
        self.log_display.config(state='normal')
        self.log_display.delete(1.0, tk.END)
        self.log_display.config(state='disabled')
        logging.info("تم مسح شاشة النتائج.")


# --- فئة لإعادة توجيه المخرجات إلى الواجهة ---
class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.configure(state='disabled')
            self.text_widget.yview(tk.END)
        self.text_widget.after(0, append)


if __name__ == "__main__":
    if platform.system() == "Linux" and os.geteuid() != 0:
        messagebox.showwarning("صلاحيات مطلوبة", "للحصول على أفضل النتائج، يرجى تشغيل التطبيق باستخدام صلاحيات الجذر (sudo).")
    
    app = App()
    app.mainloop()
