import psutil
import platform
import os
import logging
import requests
from datetime import datetime
import hashlib
import json
import shutil
import subprocess
import time

# --- المفتاح المدمج ---
# تم وضع المفتاح هنا مباشرة في الكود
VT_API_KEY = "D021a9a0b00adc6788c88df141e60cf5fa51039032383f5f11550761ed29a286"


# --- الوحدة 1: تحليل الشبكة ---
def check_ip_reputation(ip_address):
    """
    يستخدم واجهة برمجية مجانية للتحقق من سمعة عنوان IP.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,proxy,hosting,query", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                is_proxy = data.get('proxy', False)
                is_hosting = data.get('hosting', False)
                if is_proxy or is_hosting:
                    return f"تحذير: IP قد يكون بروكسي/استضافة ({'Proxy' if is_proxy else ''}{'Hosting' if is_hosting else ''})"
                return "سمعة IP تبدو طبيعية"
    except requests.RequestException:
        return "لا يمكن التحقق من سمعة IP"
    return "غير معروف"

def network_analysis():
    """
    تحليل الاتصالات الشبكية النشطة والتحقق من سمعة عناوين IP الخارجية.
    """
    logging.info("--- بدء تحليل الشبكة ---")
    suspicious_found = False
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                proc_name = "N/A"
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                ip_rep = check_ip_reputation(conn.raddr.ip)
                if "تحذير" in ip_rep:
                    logging.warning(f"اتصال مشبوه: العملية '{proc_name}' (PID: {conn.pid}) متصلة بـ {conn.raddr.ip}:{conn.raddr.port} [{ip_rep}]")
                    suspicious_found = True

    except Exception as e:
        logging.error(f"حدث خطأ أثناء تحليل الشبكة: {e}")
    
    if not suspicious_found:
        logging.info("لم يتم العثور على اتصالات شبكية مشبوهة.")

# --- الوحدة 2: تحليل العمليات ---
def process_analysis():
    """
    تحليل العمليات قيد التشغيل للبحث عن مؤشرات مشبوهة.
    """
    logging.info("--- بدء تحليل العمليات النشطة ---")
    suspicious_found = False
    suspicious_locations = ["/tmp", "/var/tmp", "/dev/shm"]
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
        try:
            if proc.info['exe'] and any(proc.info['exe'].startswith(loc) for loc in suspicious_locations if loc):
                logging.warning(f"عملية مشبوهة: '{proc.info['name']}' (PID: {proc.info['pid']}) تعمل من مسار مؤقت: {proc.info['exe']}")
                suspicious_found = True
            
            proc_age_seconds = datetime.now().timestamp() - proc.info['create_time']
            if proc_age_seconds < 60:
                logging.info(f"عملية حديثة: '{proc.info['name']}' (PID: {proc.info['pid']}) بدأت قبل {int(proc_age_seconds)} ثانية.")

        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue
            
    if not suspicious_found:
        logging.info("لم يتم العثور على عمليات تعمل من مواقع مشبوهة.")

# --- الوحدة 3: فحص آليات الإقلاع التلقائي (Persistence) ---
def persistence_analysis():
    """
    فحص آليات الإقلاع التلقائي بناءً على نظام التشغيل.
    """
    logging.info("--- بدء فحص آليات الإقلاع التلقائي ---")
    os_type = platform.system()
    
    if os_type == "Windows":
        check_windows_startup()
    elif os_type == "Linux":
        check_linux_startup()
    else:
        logging.warning(f"نظام التشغيل '{os_type}' غير مدعوم حاليًا لفحص الإقلاع التلقائي.")

def check_windows_startup():
    """فحص مفاتيح الريجستري ومجلدات بدء التشغيل في ويندوز."""
    try:
        import winreg
        logging.info("فحص برامج بدء التشغيل في Windows...")
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        for hive, key_path in run_keys:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            logging.info(f"  [Registry] {name}: {value}")
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                logging.info(f"مفتاح الريجستري غير موجود: {key_path}")
            except Exception as e:
                logging.error(f"لا يمكن الوصول إلى مفتاح الريجستري (قد تحتاج إلى صلاحيات مسؤول): {key_path} - {e}")
    except ImportError:
        logging.error("مكتبة 'winreg' متاحة فقط على نظام ويندوز.")

def check_linux_startup():
    """فحص خدمات systemd ومهام cron في لينكس."""
    logging.info("فحص خدمات systemd ومهام cron في Linux...")
    
    systemd_paths = [
        "/etc/systemd/system/",
        os.path.expanduser("~/.config/systemd/user/")
    ]
    for path in systemd_paths:
        if os.path.isdir(path):
            try:
                for service in os.listdir(path):
                    if service.endswith(".service"):
                        logging.info(f"  [Systemd] {os.path.join(path, service)}")
            except OSError as e:
                logging.error(f"لا يمكن قراءة المسار {path}: {e}")

    cron_paths = [
        "/etc/crontab",
        "/var/spool/cron/crontabs/"
    ]
    for path in cron_paths:
        if os.path.exists(path):
            logging.info(f"  [Cron] تم العثور على ملفات/مجلدات cron في: {path}")

# --- الوحدة 4: مراقبة سلامة الملفات (FIM) ---
def _calculate_hash(filepath):
    """حساب بصمة SHA-256 لملف معين."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, PermissionError):
        return None

def _get_files_from_paths(paths_file):
    """الحصول على قائمة بجميع الملفات من المسارات المحددة."""
    all_files = set()
    try:
        with open(paths_file, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logging.error(f"ملف المسارات '{paths_file}' غير موجود.")
        return all_files

    for path in paths:
        if os.path.isfile(path):
            all_files.add(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for filename in files:
                    all_files.add(os.path.join(root, filename))
    return all_files

def create_baseline(paths_file, baseline_file):
    """إنشاء خط أساس لبصمات الملفات."""
    logging.info(f"--- بدء إنشاء خط الأساس من '{paths_file}' ---")
    baseline = {}
    files_to_scan = _get_files_from_paths(paths_file)
    
    if not files_to_scan:
        logging.warning("لم يتم العثور على ملفات لإنشاء خط الأساس.")
        return

    for filepath in files_to_scan:
        file_hash = _calculate_hash(filepath)
        if file_hash:
            baseline[filepath] = file_hash
    
    try:
        with open(baseline_file, 'w') as f:
            json.dump(baseline, f, indent=4)
        logging.info(f"[+] تم حفظ خط الأساس بنجاح في '{baseline_file}' لـ {len(baseline)} ملف.")
    except IOError as e:
        logging.error(f"فشل حفظ ملف خط الأساس: {e}")

def verify_integrity(paths_file, baseline_file):
    """التحقق من سلامة الملفات بمقارنتها بخط الأساس."""
    logging.info(f"--- بدء التحقق من سلامة الملفات باستخدام '{baseline_file}' ---")
    try:
        with open(baseline_file, 'r') as f:
            baseline = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"لا يمكن تحميل ملف خط الأساس '{baseline_file}'. يرجى إنشاؤه أولاً. الخطأ: {e}")
        return

    current_files_state = {}
    files_to_scan = _get_files_from_paths(paths_file)

    for filepath in files_to_scan:
        file_hash = _calculate_hash(filepath)
        if file_hash:
            current_files_state[filepath] = file_hash

    baseline_set = set(baseline.keys())
    current_set = set(current_files_state.keys())

    new_files = current_set - baseline_set
    deleted_files = baseline_set - current_set
    
    modified_files = set()
    for filepath in baseline_set.intersection(current_set):
        if baseline[filepath] != current_files_state[filepath]:
            modified_files.add(filepath)

    if not new_files and not deleted_files and not modified_files:
        logging.info("[+] تم التحقق من سلامة جميع الملفات. لم يتم العثور على أي تغييرات.")
    else:
        if new_files:
            logging.warning(f"\n[!] تم العثور على {len(new_files)} ملف جديد:")
            for f in new_files:
                logging.warning(f"  - {f}")
        if deleted_files:
            logging.warning(f"\n[!] تم حذف {len(deleted_files)} ملف:")
            for f in deleted_files:
                logging.warning(f"  - {f}")
        if modified_files:
            logging.critical(f"\n[!!!] تم تعديل {len(modified_files)} ملف:")
            for f in modified_files:
                logging.critical(f"  - {f}")

# --- الوحدة 5: مكافحة الفيروسات والتنظيف ---
def _load_signatures(sig_file):
    """تحميل بصمات الفيروسات من الملف."""
    signatures = {}
    try:
        with open(sig_file, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    parts = line.strip().split(':')
                    if len(parts) == 2:
                        signatures[parts[0]] = parts[1]
    except FileNotFoundError:
        logging.error(f"ملف بصمات الفيروسات '{sig_file}' غير موجود.")
    return signatures

def scan_for_viruses(scan_path, sig_file, quarantine_dir, vt_api_key=VT_API_KEY):
    """فحص مسار معين بحثًا عن ملفات تطابق بصمات الفيروسات."""
    logging.info(f"--- بدء فحص الفيروسات في المسار: {scan_path} ---")
    signatures = _load_signatures(sig_file)
    if not signatures and not vt_api_key:
        logging.warning("قاعدة بيانات الفيروسات فارغة ولم يتم توفير مفتاح VirusTotal. سيتوقف الفحص.")
        return

    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
        logging.info(f"تم إنشاء مجلد العزل: {quarantine_dir}")

    threats_found = 0
    for root, _, files in os.walk(scan_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = _calculate_hash(filepath)
            if not file_hash: continue

            threat_name = None
            if file_hash in signatures:
                threat_name = signatures[file_hash]
            elif vt_api_key:
                logging.info(f"فحص بصمة الملف {filename} عبر VirusTotal...")
                vt_result = check_hash_with_virustotal(file_hash)
                if vt_result and vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    malicious_count = vt_result['data']['attributes']['last_analysis_stats']['malicious']
                    threat_name = f"VirusTotal ({malicious_count} detections)"

            if threat_name:
                threats_found += 1
                logging.critical(f"[!!!] تم العثور على تهديد: {threat_name}")
                logging.critical(f"  - الملف المصاب: {filepath}")
                try:
                    shutil.move(filepath, os.path.join(quarantine_dir, filename))
                    logging.warning(f"  - تم نقل الملف بنجاح إلى مجلد العزل.")
                except Exception as e:
                    logging.error(f"  - فشل نقل الملف إلى مجلد العزل: {e}")

    if threats_found == 0:
        logging.info("[+] الفحص انتهى. لم يتم العثور على أي تهديدات.")
    else:
        logging.info(f"انتهى الفحص. إجمالي التهديدات المكتشفة: {threats_found}")

def clean_junk_files(rules_file):
    """تنظيف الملفات الزائدة بناءً على القواعد المحددة."""
    logging.info("--- بدء البحث عن الملفات الزائدة لتنظيفها ---")
    try:
        with open(rules_file, 'r') as f:
            rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logging.error(f"ملف قواعد التنظيف '{rules_file}' غير موجود.")
        return

    files_to_delete = []
    for rule in rules:
        if rule.startswith('/'):
            if os.path.isdir(rule):
                for root, _, files in os.walk(rule):
                    for filename in files:
                        files_to_delete.append(os.path.join(root, filename))
        else:
            for root, _, files in os.walk('/'):
                for filename in files:
                    if filename.endswith(rule):
                        files_to_delete.append(os.path.join(root, filename))
    
    if not files_to_delete:
        logging.info("[+] لم يتم العثور على أي ملفات زائدة.")
        return

    logging.warning(f"تم العثور على {len(files_to_delete)} ملف زائد.")
    confirm = input("هل أنت متأكد أنك تريد حذف هذه الملفات بشكل نهائي؟ (اكتب 'نعم' للتأكيد): ")

    if confirm.lower() == 'نعم':
        deleted_count = 0
        for filepath in files_to_delete:
            try:
                os.remove(filepath)
                deleted_count += 1
            except Exception as e:
                logging.error(f"فشل حذف الملف {filepath}: {e}")
        logging.info(f"[+] تم حذف {deleted_count} ملف بنجاح.")
    else:
        logging.info("تم إلغاء عملية الحذف.")

# --- الوحدة 6: إدارة البرامج وإزالتها ---
def list_installed_packages():
    """عرض قائمة بالبرامج المثبتة على النظام (يعمل على أنظمة Debian/Ubuntu)."""
    logging.info("--- عرض البرامج المثبتة (قد يستغرق بعض الوقت) ---")
    os_type = platform.system()
    if os_type != "Linux":
        logging.error("هذه الميزة مدعومة حاليًا على نظام لينكس فقط.")
        return
    try:
        result = subprocess.run(['dpkg', '--list'], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        print(lines[4]) 
        for line in lines[5:]:
            print(line)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"فشل في عرض البرامج: {e}.")

def deep_uninstall_package(package_name):
    """إزالة برنامج من جذوره، بما في ذلك ملفات الإعدادات والبقايا."""
    logging.info(f"--- بدء عملية الإزالة العميقة للحزمة: {package_name} ---")
    os_type = platform.system()
    if os_type != "Linux":
        logging.error("هذه الميزة مدعومة حاليًا على نظام لينكس فقط.")
        return
    try:
        logging.info(f"[1/3] إزالة الحزمة '{package_name}' وملفات الإعدادات...")
        subprocess.run(['sudo', 'apt-get', 'purge', '-y', package_name], check=True)
        logging.info("تمت إزالة الحزمة بنجاح.")
        logging.info("[2/3] تنظيف الاعتماديات غير المستخدمة...")
        subprocess.run(['sudo', 'apt-get', 'autoremove', '-y'], check=True)
        logging.info("تم تنظيف الاعتماديات.")
        logging.info(f"[3/3] البحث عن الملفات المتبقية المتعلقة بـ '{package_name}'...")
        search_paths = [os.path.expanduser('~/.config'), os.path.expanduser('~/.cache'), '/etc', '/opt', '/var/lib']
        leftovers = []
        for path in search_paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    if package_name in dirs:
                        leftovers.append(os.path.join(root, package_name))
                    for f in files:
                        if package_name in f:
                            leftovers.append(os.path.join(root, f))
        if not leftovers:
            logging.info("[+] لم يتم العثور على أي ملفات متبقية. عملية الإزالة نظيفة.")
            return
        logging.warning(f"\nتم العثور على {len(leftovers)} ملف/مجلد قد يكون متبقيًا:")
        for item in leftovers:
            print(f"  - {item}")
        confirm = input("\nهل تريد حذف هذه الملفات والمجلدات بشكل نهائي؟ (اكتب 'نعم' للتأكيد): ")
        if confirm.lower() == 'نعم':
            deleted_count = 0
            for item in leftovers:
                try:
                    if os.path.isdir(item):
                        shutil.rmtree(item)
                    else:
                        os.remove(item)
                    deleted_count += 1
                except Exception as e:
                    logging.error(f"فشل حذف {item}: {e}")
            logging.info(f"تم حذف {deleted_count} من الملفات/المجلدات المتبقية.")
        else:
            logging.info("تم إلغاء عملية حذف الملفات المتبقية.")
    except subprocess.CalledProcessError as e:
        logging.error(f"فشلت عملية الإزالة. قد تكون الحزمة غير موجودة أو حدث خطأ آخر: {e}")
    except Exception as e:
        logging.error(f"حدث خطأ غير متوقع: {e}")

# --- الوحدة 7: فحص الشيفرة المصدرية ---
def scan_source_code(scan_path):
    """
    فحص الأكواد المصدرية في مسار معين بحثًا عن دوال وأنماط خطيرة.
    """
    logging.info(f"--- بدء فحص الأكواد المصدرية في: {scan_path} ---")
    target_files = {'.php': ['eval(', 'exec(', 'shell_exec(', 'passthru(', 'system('], '.js': ['eval(', 'new Function('], '.py': ['eval(', 'exec(', 'os.system(']}
    threats_found = 0
    if not os.path.isdir(scan_path):
        logging.error(f"المسار '{scan_path}' غير موجود أو ليس مجلدًا.")
        return
    for root, _, files in os.walk(scan_path):
        for filename in files:
            file_ext = os.path.splitext(filename)[1]
            if file_ext in target_files:
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for dangerous_pattern in target_files[file_ext]:
                            if dangerous_pattern in content:
                                threats_found += 1
                                logging.warning(f"[!] تم العثور على نمط خطير '{dangerous_pattern}' في الملف: {filepath}")
                except Exception as e:
                    logging.error(f"لا يمكن قراءة الملف {filepath}: {e}")
    if threats_found == 0:
        logging.info("[+] الفحص انتهى. لم يتم العثور على أي أنماط خطيرة في الأكواد.")
    else:
        logging.info(f"انتهى الفحص. إجمالي التهديدات المحتملة المكتشفة: {threats_found}")

# --- الوحدة 8: التدقيق الأمني الشامل ---
def check_firewall_status():
    """التحقق من حالة جدار الحماية في النظام."""
    logging.info("--- [التدقيق] التحقق من حالة جدار الحماية ---")
    os_type = platform.system()
    try:
        if os_type == "Linux":
            result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, check=True)
            if "Status: active" in result.stdout:
                logging.info("[+] جدار الحماية (ufw) نشط ويعمل.")
            else:
                logging.warning("[!] جدار الحماية (ufw) غير نشط.")
        elif os_type == "Windows":
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], capture_output=True, text=True, check=True)
            if "State" in result.stdout and "ON" in result.stdout.upper():
                 logging.info("[+] جدار الحماية في ويندوز نشط.")
            else:
                logging.warning("[!] جدار الحماية في ويندوز قد يكون معطلاً.")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logging.error(f"لا يمكن التحقق من حالة جدار الحماية: {e}")

def check_insecure_permissions():
    """البحث عن ملفات ذات صلاحيات غير آمنة في مسارات النظام."""
    logging.info("--- [التدقيق] البحث عن صلاحيات غير آمنة ---")
    paths_to_check = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
    found_insecure = False
    for path in paths_to_check:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        mode = os.stat(filepath).st_mode
                        if mode & 0o002:
                            logging.warning(f"[!] تم العثور على صلاحيات غير آمنة (world-writable): {filepath}")
                            found_insecure = True
                    except FileNotFoundError:
                        continue
    if not found_insecure:
        logging.info("[+] لم يتم العثور على ملفات بصلاحيات غير آمنة في مسارات النظام.")

def check_upgradable_packages():
    """التحقق من وجود تحديثات للبرامج المثبتة (لأنظمة Debian/Ubuntu)."""
    logging.info("--- [التدقيق] البحث عن برامج تحتاج إلى تحديث ---")
    os_type = platform.system()
    if os_type != "Linux":
        logging.warning("هذه الميزة مدعومة حاليًا على نظام لينكس فقط.")
        return
    try:
        subprocess.run(['sudo', 'apt-get', 'update'], capture_output=True, text=True)
        result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
        if len(lines) <= 1:
            logging.info("[+] جميع البرامج محدثة.")
        else:
            logging.warning(f"[!] تم العثور على {len(lines) - 1} برنامج يحتاج إلى تحديث:")
            for line in lines[1:]:
                print(f"  - {line.split('/')[0]}")
    except FileNotFoundError:
        logging.error("الأمر 'apt' غير موجود. هل أنت على نظام يستخدمه؟")

def check_cve_vulnerabilities(package_name):
    """البحث عن ثغرات أمنية معروفة (CVEs) لحزمة معينة."""
    logging.info(f"--- البحث عن ثغرات CVE للحزمة: {package_name} ---")
    try:
        url = f"https://cve.circl.lu/api/search/{package_name}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200 and response.json():
            vulnerabilities = response.json().get('data', [])
            if not vulnerabilities:
                logging.info(f"[+] لم يتم العثور على ثغرات CVE معروفة لـ '{package_name}'.")
                return
            
            logging.warning(f"[!] تم العثور على {len(vulnerabilities)} ثغرة محتملة لـ '{package_name}':")
            for vuln in vulnerabilities[:5]:
                summary = vuln.get('summary', 'لا يوجد وصف')
                cve_id = vuln.get('id', 'N/A')
                print(f"  - {cve_id}: {summary}")
        else:
            logging.info(f"[+] لم يتم العثور على ثغرات CVE معروفة لـ '{package_name}'.")
    except requests.RequestException as e:
        logging.error(f"حدث خطأ أثناء البحث عن ثغرات CVE: {e}")

def check_environment_variables():
    """البحث عن متغيرات بيئة قد تحتوي على بيانات حساسة."""
    logging.info("--- [التدقيق] فحص متغيرات البيئة الحساسة ---")
    sensitive_vars = ['API_KEY', 'PASSWORD', 'SECRET', 'TOKEN', 'PASS', 'KEY']
    found_sensitive = False
    for var, value in os.environ.items():
        for sensitive in sensitive_vars:
            if sensitive in var.upper():
                logging.warning(f"[!] تم العثور على متغير بيئة حساس: {var}")
                found_sensitive = True
                break
    if not found_sensitive:
        logging.info("[+] لم يتم العثور على متغيرات بيئة حساسة.")

def run_security_audit():
    """تشغيل جميع وحدات التدقيق الأمني."""
    logging.info("==============================================")
    logging.info("        بدء التدقيق الأمني الشامل للجهاز        ")
    logging.info("==============================================")
    check_firewall_status()
    check_insecure_permissions()
    check_upgradable_packages()
    check_environment_variables()
    logging.info("--- انتهى التدقيق الأمني ---")

# --- الوحدة 9: اكتشاف الشبكة ---
def discover_network_devices(network_range):
    """اكتشاف الأجهزة النشطة على الشبكة المحلية باستخدام nmap."""
    logging.info(f"--- بدء اكتشاف الأجهزة على الشبكة: {network_range} ---")
    try:
        import nmap
    except ImportError:
        logging.error("مكتبة 'python-nmap' غير مثبتة. يرجى تشغيل 'pip install python-nmap'.")
        return

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network_range, arguments='-sn')
        
        if not nm.all_hosts():
            logging.info("لم يتم العثور على أي أجهزة نشطة في هذا النطاق.")
            return
            
        logging.info(f"تم العثور على {len(nm.all_hosts())} جهاز نشط:")
        for host in nm.all_hosts():
            status = nm[host].state()
            vendor = ""
            if 'vendor' in nm[host] and nm[host]['vendor']:
                vendor = f" ({list(nm[host]['vendor'].values())[0]})"
            print(f"  - IP: {host:<15} | Status: {status}{vendor}")
            
    except nmap.PortScannerError:
        logging.error("خطأ في Nmap. هل قمت بتثبيت Nmap على نظامك (sudo apt-get install nmap)؟")
    except Exception as e:
        logging.error(f"حدث خطأ غير متوقع أثناء اكتشاف الشبكة: {e}")

# --- الوحدة 10: فحص تطبيقات أندرويد عبر MobSF ---
def analyze_apk_with_mobsf(apk_path, mobsf_server, api_key):
    """
    يقوم برفع وفحص ملف APK باستخدام واجهة MobSF API ويعرض ملخصًا للنتائج.
    """
    logging.info("==============================================")
    logging.info(f"   بدء فحص ملف APK عبر MobSF: {os.path.basename(apk_path)}   ")
    logging.info("==============================================")

    if not os.path.exists(apk_path):
        logging.error(f"الملف '{apk_path}' غير موجود.")
        return

    headers = {'Authorization': api_key}
    
    logging.info("[1/4] رفع الملف إلى خادم MobSF...")
    try:
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f)}
            response_upload = requests.post(f"{mobsf_server}/api/v1/upload", headers=headers, files=files, timeout=300)
            
        if response_upload.status_code != 200:
            logging.error(f"فشل رفع الملف. استجابة الخادم: {response_upload.status_code} - {response_upload.text}")
            return
        
        upload_data = response_upload.json()
        logging.info("[+] تم رفع الملف بنجاح.")
    except Exception as e:
        logging.error(f"حدث خطأ أثناء رفع الملف: {e}")
        return

    logging.info("[2/4] بدء عملية الفحص على الخادم...")
    try:
        scan_payload = {
            'scan_type': upload_data['scan_type'],
            'hash': upload_data['hash']
        }
        response_scan = requests.post(f"{mobsf_server}/api/v1/scan", headers=headers, data=scan_payload, timeout=30)
        
        if response_scan.status_code != 200:
            logging.error(f"فشل بدء الفحص. استجابة الخادم: {response_scan.status_code} - {response_scan.text}")
            return
        
        logging.info("[+] بدأت عملية الفحص. قد يستغرق هذا عدة دقائق...")
    except Exception as e:
        logging.error(f"حدث خطأ أثناء بدء الفحص: {e}")
        return

    logging.info("[3/4] انتظار النتائج والحصول على التقرير...")
    report_data = None
    for i in range(20):
        time.sleep(30)
        try:
            response_report = requests.post(f"{mobsf_server}/api/v1/report_json", headers=headers, data={'hash': upload_data['hash']}, timeout=30)
            if response_report.status_code == 200:
                report_data = response_report.json()
                if report_data.get('analysis_finished'):
                    logging.info("[+] تم استلام التقرير بنجاح.")
                    break
                else:
                    logging.info("الفحص لا يزال جاريًا...")
            else:
                 logging.warning(f"لم يتم العثور على تقرير بعد. المحاولة مرة أخرى...")
        except Exception as e:
            logging.error(f"حدث خطأ أثناء طلب التقرير: {e}")
            return
    
    if not report_data or not report_data.get('analysis_finished'):
        logging.error("فشل الحصول على التقرير النهائي بعد عدة محاولات.")
        return

    logging.info("\n--- [ ملخص تقرير MobSF ] ---")
    try:
        print(f"اسم التطبيق: {report_data.get('app_name', 'N/A')}")
        print(f"اسم الحزمة: {report_data.get('package_name', 'N/A')}")
        print(f"التقييم الأمني: {report_data.get('security_score', 'N/A')}/100")
        
        if 'high' in report_data.get('results', {}):
            print("\n[!] الثغرات الخطيرة (High):")
            for issue in report_data['results']['high']:
                print(f"  - {issue['title']}")

        if 'permissions' in report_data and any(p['status'] == 'dangerous' for p in report_data['permissions'].values()):
            print("\n[!] الصلاحيات الخطيرة (Dangerous Permissions):")
            for perm, details in report_data['permissions'].items():
                if details['status'] == 'dangerous':
                    print(f"  - {perm}: {details['description']}")
        
        if 'trackers' in report_data and report_data['trackers']:
            print(f"\n[!] تم العثور على {len(report_data['trackers'])} أداة تتبع:")
            for tracker in report_data['trackers']:
                print(f"  - {tracker['name']}")
                
    except Exception as e:
        logging.error(f"حدث خطأ أثناء تحليل التقرير: {e}")

# --- الدالة الرئيسية للفحص ---
def run_host_scan():
    """
    الدالة الرئيسية لتشغيل الفحوصات التقليدية.
    """
    logging.info("==============================================")
    logging.info("   بدء فحص مؤشرات الاختراق على الجهاز المحلي   ")
    logging.info("==============================================")
    network_analysis()
    process_analysis()
    persistence_analysis()
    logging.info("--- انتهى فحص الجهاز ---")
