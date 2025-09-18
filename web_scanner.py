import requests
import logging
import threading
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from packaging import version as packaging_version

class Scanner:
    def __init__(self, base_url, max_threads=10, user_agent=None, cookie=None, exclude_urls=None, max_depth=3, policy='full', output_file=None, login_url=None, login_data=None, scan_subdomains=False, check_dependencies=False):
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.session = requests.Session()
        
        headers = {
            'User-Agent': user_agent if user_agent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        if cookie:
            headers['Cookie'] = cookie
        self.session.headers.update(headers)
        
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.policy = policy
        self.output_file = output_file
        self.exclude_urls = exclude_urls or []
        self.crawled_urls = set()
        self.vulnerabilities = []
        self.lock = threading.Lock()

        self.login_url = login_url
        self.login_data = login_data
        
        self.scan_subdomains = scan_subdomains
        self.discovered_subdomains = []

        # --- متغير جديد لفحص المكتبات ---
        self.check_dependencies = check_dependencies
        self.vulnerability_db = self._load_vulnerability_db()
        self.scanned_scripts = set() # لمنع فحص نفس المكتبة أكثر من مرة

    def _load_vulnerability_db(self):
        """تحميل قاعدة بيانات الثغرات من ملف JSON."""
        try:
            with open('vulnerability_db.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logging.error("لا يمكن تحميل قاعدة بيانات الثغرات 'vulnerability_db.json'.")
            return {}

    def _scan_dependencies(self, url):
        """فحص مكتبات جافا سكريبت القديمة في صفحة معينة."""
        if not self.check_dependencies or not self.vulnerability_db:
            return
        
        logging.info(f"--- بدء فحص المكتبات في: {url} ---")
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for script_tag in soup.find_all('script', src=True):
                script_src = script_tag['src']
                
                # تخطي إذا تم فحص هذا السكريبت من قبل
                if script_src in self.scanned_scripts:
                    continue
                self.scanned_scripts.add(script_src)

                # محاولة استخراج اسم المكتبة والإصدار من الرابط
                # هذا النمط يبحث عن (اسم المكتبة)-(رقم الإصدار).js
                match = re.search(r'/([a-zA-Z0-9_.-]+)-(\d+\.\d+(\.\d+)*.*?)\.js', script_src)
                if not match:
                    continue

                library_name = match.group(1).lower()
                detected_version_str = match.group(2)
                
                # تجاهل المكتبات غير الموجودة في قاعدة البيانات
                if library_name not in self.vulnerability_db:
                    continue
                
                try:
                    detected_version = packaging_version.parse(detected_version_str)
                    
                    # مقارنة الإصدار المكتشف مع الثغرات المعروفة
                    for vuln in self.vulnerability_db[library_name]:
                        vulnerable_range = vuln['vulnerable_versions']
                        # هذا الجزء يتحقق من الشروط مثل "<3.5.0"
                        if vulnerable_range.startswith('<'):
                            max_version = packaging_version.parse(vulnerable_range.lstrip('<='))
                            if detected_version < max_version:
                                details = f"تم العثور على مكتبة '{library_name}' بإصدار قديم ({detected_version_str}). الإصدارات {vulnerable_range} معروفة بأنها مصابة بـ {vuln['cve']}: {vuln['description']}"
                                logging.critical(f"[مكتبة قديمة] {details}")
                                self.add_vulnerability({
                                    "url": url, "type": "Vulnerable Dependency", "severity": "High",
                                    "details": details, "payload": script_src
                                })
                except packaging_version.InvalidVersion:
                    logging.warning(f"لا يمكن تحليل رقم الإصدار: {detected_version_str}")

        except requests.RequestException:
            pass

    def run_web_scan(self):
        logging.info("==============================================")
        logging.info(f"         بدء فحص الموقع: {self.base_url}         ")
        logging.info("==============================================")
        
        self._enumerate_subdomains()
        self._perform_login()
        
        targets_to_scan = [self.base_url] + self.discovered_subdomains
        for target in targets_to_scan:
            self.crawl(target)
        logging.info(f"انتهى الزحف، تم العثور على {len(self.crawled_urls)} صفحة فريدة.")

        self._scan_sensitive_files()
        
        logging.info("--- بدء فحص الصفحات المكتشفة ---")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.scan_page, self.crawled_urls)

        self.generate_report()

    def scan_page(self, url):
        logging.info(f"فحص الصفحة: {url}")
        if self.policy in ['full', 'passive']:
            self._scan_http_headers(url)
            self._scan_dependencies(url) # <-- إضافة الفحص الجديد هنا
        if self.policy in ['full', 'injection']:
            self._scan_xss(url)
            self._scan_sqli(url)

    # --- باقي دوال الفئة تبقى كما هي ---
    # ... (انسخ باقي الدوال من الإصدار السابق هنا)
    def _enumerate_subdomains(self):
        if not self.scan_subdomains: return
        logging.info("--- بدء البحث عن النطاقات الفرعية ---")
        subdomain_list = self.load_payloads('subdomains.txt')
        if not subdomain_list:
            logging.warning("لم يتم العثور على قائمة النطاقات الفرعية (subdomains.txt).")
            return
        live_subdomains = []
        def check_subdomain(sub):
            for protocol in ["https://", "http://"]:
                url = f"{protocol}{sub}.{self.domain_name}"
                try:
                    self.session.get(url, timeout=5, allow_redirects=True)
                    logging.info(f"[+] تم العثور على نطاق فرعي نشط: {url}")
                    live_subdomains.append(url)
                    break
                except requests.RequestException:
                    continue
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(check_subdomain, subdomain_list)
        self.discovered_subdomains = live_subdomains
        logging.info(f"--- انتهى البحث، تم العثور على {len(live_subdomains)} نطاق فرعي نشط. ---")

    def _perform_login(self):
        if not self.login_url or not self.login_data: return
        logging.info(f"--- محاولة تسجيل الدخول عبر {self.login_url} ---")
        try:
            login_page_res = self.session.get(self.login_url, timeout=15)
            soup = BeautifulSoup(login_page_res.content, 'html.parser')
            form = soup.find('form')
            if not form:
                logging.error("[-] لم يتم العثور على أي نموذج في صفحة تسجيل الدخول.")
                return
            action_url = urljoin(self.login_url, form.attrs.get('action', ''))
            method = form.attrs.get('method', 'post').lower()
            post_data = dict(item.split('=') for item in self.login_data.split('&'))
            logging.info(f"إرسال بيانات الدخول إلى: {action_url}")
            if method == 'post':
                response = self.session.post(action_url, data=post_data, timeout=15, allow_redirects=True)
            else:
                response = self.session.get(action_url, params=post_data, timeout=15, allow_redirects=True)
            if "logout" in response.text.lower() or "sign out" in response.text.lower() or "log out" in response.text.lower():
                logging.info("[+] تم تسجيل الدخول بنجاح.")
            else:
                logging.warning("[-] فشل تسجيل الدخول أو لم يتم العثور على دليل على النجاح.")
        except Exception as e:
            logging.error(f"حدث خطأ أثناء محاولة تسجيل الدخول: {e}")

    def load_payloads(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.warning(f"ملف الحمولات '{filename}' غير موجود.")
            return []

    def crawl(self, url, depth=0):
        if url in self.crawled_urls or depth >= self.max_depth: return
        parsed_url = urlparse(url)
        if not parsed_url.netloc.endswith(self.domain_name): return
        if any(excluded in url for excluded in self.exclude_urls): return
        with self.lock:
            if url in self.crawled_urls: return
            self.crawled_urls.add(url)
        logging.info(f"الزحف (العمق: {depth}): {url}")
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(response.content, "html.parser")
            for a_tag in soup.find_all('a', href=True):
                link = urljoin(url, a_tag['href'])
                self.crawl(link, depth + 1)
        except requests.RequestException as e:
            logging.error(f"فشل الزحف إلى {url}: {e}")

    def get_form_details(self, form):
        details = {'action': form.attrs.get('action', '').lower(), 'method': form.attrs.get('method', 'get').lower(), 'inputs': []}
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            details['inputs'].append({'type': input_tag.attrs.get('type', 'text'), 'name': input_tag.attrs.get('name')})
        return details

    def submit_form(self, form_details, url, payload):
        target_url = urljoin(url, form_details['action'])
        data = {item['name']: payload for item in form_details['inputs'] if item.get('name')}
        try:
            if form_details['method'] == 'post':
                return self.session.post(target_url, data=data, timeout=10)
            else:
                return self.session.get(target_url, params=data, timeout=10)
        except requests.RequestException:
            return None

    def add_vulnerability(self, vulnerability):
        with self.lock:
            self.vulnerabilities.append(vulnerability)

    def _scan_http_headers(self, url):
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            security_headers = {'Content-Security-Policy': 'High', 'Strict-Transport-Security': 'Medium', 'X-Content-Type-Options': 'Low', 'X-Frame-Options': 'Low'}
            for header, severity in security_headers.items():
                if header not in headers:
                    details = f"رأس الأمان '{header}' مفقود."
                    logging.warning(f"[فحص الرؤوس] {details} في {url}")
                    self.add_vulnerability({"url": url, "type": "Missing Security Header", "severity": severity, "details": details, "payload": "N/A"})
        except requests.RequestException:
            pass

    def _scan_sensitive_files(self):
        logging.info("--- بدء البحث عن الملفات الحساسة ---")
        paths = self.load_payloads('sensitive_paths.txt')
        for path in paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=7)
                if response.status_code == 200:
                    details = f"تم العثور على ملف/مسار حساس يمكن الوصول إليه: {path}"
                    logging.critical(f"[ملفات حساسة] {details}")
                    self.add_vulnerability({"url": url, "type": "Sensitive File Exposure", "severity": "High", "details": details, "payload": path})
            except requests.RequestException:
                pass

    def _scan_generic_injection(self, url, scan_type, payloads_file, check_func, severity, log_message):
        payloads = self.load_payloads(payloads_file)
        if not payloads: return
        try:
            response = self.session.get(url, timeout=10)
            forms = BeautifulSoup(response.content, 'html.parser').find_all('form')
            for form in forms:
                form_details = self.get_form_details(form)
                for payload in payloads:
                    res = self.submit_form(form_details, url, payload)
                    if res and check_func(res, payload):
                        details = f"تم اكتشاف ثغرة في النموذج action='{form_details['action']}'"
                        logging.critical(f"[{log_message}] {details} في {url}")
                        self.add_vulnerability({"url": url, "type": scan_type, "severity": severity, "details": details, "payload": payload})
                        return
        except requests.RequestException:
            pass

    def _scan_xss(self, url):
        self._scan_generic_injection(url, "Cross-Site Scripting (XSS)", 'xss_payloads.txt', lambda res, p: p in res.text, "High", "XSS")

    def _scan_sqli(self, url):
        sql_errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"]
        self._scan_generic_injection(url, "SQL Injection (SQLi)", 'sqli_payloads.txt', lambda res, p: any(e in res.text.lower() for e in sql_errors), "Critical", "SQLi")

    def generate_report(self):
        logging.info("\n--- تقرير الفحص النهائي ---")
        if not self.vulnerabilities:
            logging.info("لم يتم العثور على أي ثغرات.")
            return
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x['severity'], 99))
        logging.info(f"تم العثور على {len(sorted_vulns)} ثغرة:")
        for vuln in sorted_vulns:
            logging.warning(f"  - النوع: {vuln['type']} | الخطورة: {vuln['severity']}")
            logging.warning(f"    الرابط: {vuln['url']}")
            logging.warning(f"    التفاصيل: {vuln['details']}")
            logging.warning(f"    الحمولة: {vuln['payload']}")
        if self.output_file:
            logging.info(f"\n--- حفظ التقرير في ملف: {self.output_file} ---")
            try:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(f"""
                    <html><head><title>تقرير فحص الأمان لـ {self.domain_name}</title>
                    <style>body{{font-family:Arial,sans-serif;margin:20px;background-color:#f4f4f9}}h1,h2{{color:#333}}table{{width:100%;border-collapse:collapse;margin-top:20px}}th,td{{padding:12px;border:1px solid #ddd;text-align:left}}th{{background-color:#4CAF50;color:white}}tr:nth-child(even){{background-color:#f2f2f2}}.severity-Critical{{background-color:#d32f2f;color:white}}.severity-High{{background-color:#f44336;color:white}}.severity-Medium{{background-color:#ff9800}}.severity-Low{{background-color:#ffeb3b}}</style>
                    </head><body><h1>تقرير فحص الأمان</h1><h2>الموقع المستهدف: {self.base_url}</h2><p>تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p><p>إجمالي الثغرات المكتشفة: {len(sorted_vulns)}</p>
                    <table><tr><th>النوع</th><th>الخطورة</th><th>الرابط</th><th>التفاصيل</th><th>الحمولة المستخدمة</th></tr>""")
                    for vuln in sorted_vulns:
                        f.write(f"""<tr><td>{vuln['type']}</td><td class="severity-{vuln['severity']}">{vuln['severity']}</td><td><a href="{vuln['url']}" target="_blank">{vuln['url']}</a></td><td>{vuln['details']}</td><td>{vuln['payload']}</td></tr>""")
                    f.write("""</table></body></html>""")
                logging.info("تم حفظ التقرير بنجاح.")
            except Exception as e:
                logging.error(f"فشل حفظ التقرير: {e}")
