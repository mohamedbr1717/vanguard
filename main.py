import argparse
import logging
import sys
import os

def main():
    # إعدادات التسجيل
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

    # إعداد المحلل الرئيسي
    parser = argparse.ArgumentParser(description="Vanguard Scanner: أداة متكاملة لفحص أمان الأجهزة والمواقع.")
    subparsers = parser.add_subparsers(dest='command', required=True, help="الأوامر المتاحة")

    # --- تحديث أمر فحص الجهاز (host) ---
    parser_host = subparsers.add_parser('host', help="فحص وإدارة أمان الجهاز المحلي.")
    parser_host.add_argument(
        "--action", 
        choices=['scan', 'baseline', 'verify', 'scan-viruses', 'clean-junk', 'list-packages', 'uninstall', 'scan-code', 'audit', 'check-cve', 'discover-network', 'scan-apk'], 
        default='scan', 
        help="الإجراء المطلوب."
    )
    # خيارات عامة
    parser_host.add_argument("--scan-path", default=".", help="المسار المستهدف للفحص.")
    parser_host.add_argument("--package", help="اسم الحزمة (البرنامج) لإجراء معين.")
    parser_host.add_argument("--network", default="192.168.1.0/24", help="نطاق الشبكة المراد اكتشافها.")
    
    # خيارات FIM
    parser_host.add_argument("--baseline-file", default="baseline.json", help="مسار ملف خط الأساس.")
    parser_host.add_argument("--paths-file", default="fim_paths.txt", help="ملف المسارات المراد مراقبتها.")
    
    # خيارات AV والتنظيف
    parser_host.add_argument("--quarantine-dir", default="./quarantine", help="مجلد عزل الملفات المصابة.")
    parser_host.add_argument("--signatures", default="virus_signatures.txt", help="ملف بصمات الفيروسات.")
    parser_host.add_argument("--junk-rules", default="junk_rules.txt", help="ملف قواعد الملفات الزائدة.")
    parser_host.add_argument("--vt-key", help="مفتاح VirusTotal API الخاص بك (اختياري).")

    # --- خيارات جديدة لفحص APK ---
    parser_host.add_argument("--apk-path", help="المسار الكامل لملف APK المراد فحصه.")
    parser_host.add_argument("--mobsf-server", default="http://127.0.0.1:8000", help="عنوان خادم MobSF.")
    parser_host.add_argument("--mobsf-key", help="مفتاح API الخاص بـ MobSF.")


    # إعداد أمر فحص الويب (web)
    # ... (هذا الجزء لم يتغير)
    parser_web = subparsers.add_parser('web', help="فحص موقع ويب بحثًا عن ثغرات شائعة.")
    parser_web.add_argument("url", help="عنوان URL الكامل للموقع المراد فحصه.")
    parser_web.add_argument("-o", "--output", help="اسم ملف التقرير لحفظ النتائج فيه (يدعم .html و .pdf).")
    # ... (باقي الخيارات لم تتغير)


    args = parser.parse_args()

    if args.command == 'host':
        from host_analyzer import (run_host_scan, create_baseline, verify_integrity, scan_for_viruses, 
                                   clean_junk_files, list_installed_packages, deep_uninstall_package, 
                                   scan_source_code, run_security_audit, check_cve_vulnerabilities, 
                                   discover_network_devices, analyze_apk_with_mobsf)
        
        if sys.platform != "win32" and os.geteuid() != 0:
            logging.warning("بعض فحوصات الجهاز تتطلب صلاحيات الجذر (root) لتعمل بشكل كامل.")

        action_map = {
            'scan': run_host_scan,
            'baseline': lambda: create_baseline(args.paths_file, args.baseline_file),
            'verify': lambda: verify_integrity(args.paths_file, args.baseline_file),
            'scan-viruses': lambda: scan_for_viruses(args.scan_path, args.signatures, args.quarantine_dir, args.vt_key),
            'clean-junk': lambda: clean_junk_files(args.junk_rules),
            'list-packages': list_installed_packages,
            'uninstall': lambda: deep_uninstall_package(args.package) if args.package else logging.error("يجب تحديد الحزمة باستخدام --package"),
            'scan-code': lambda: scan_source_code(args.scan_path),
            'audit': run_security_audit,
            'check-cve': lambda: check_cve_vulnerabilities(args.package) if args.package else logging.error("يجب تحديد الحزمة باستخدام --package"),
            'discover-network': lambda: discover_network_devices(args.network),
            'scan-apk': lambda: analyze_apk_with_mobsf(args.apk_path, args.mobsf_server, args.mobsf_key) if args.apk_path and args.mobsf_key else logging.error("يجب تحديد مسار APK ومفتاح MobSF API.")
        }
        
        # تنفيذ الإجراء المطلوب
        if args.action in action_map:
            action_map[args.action]()

    elif args.command == 'web':
        # ... (هذا الجزء لم يتغير)
        pass

if __name__ == "__main__":
    main()
