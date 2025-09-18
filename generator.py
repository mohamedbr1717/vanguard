                                                                                  import logging
from datetime import datetime

def generate_html_report(vulnerabilities, base_url, filename):
    """
    ينشئ تقرير HTML بالنتائج التي تم العثور عليها.
    """
    severity_colors = {
        "Critical": "#d9534f",
        "High": "#f0ad4e",
        "Medium": "#5bc0de",
        "Low": "#777"
    }
    html_content = f"""
    <html><head><title>Vanguard - تقرير فحص الثغرات</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; direction: rtl; text-align: right; }}
        h1, h2 {{ color: #333; border-bottom: 2px solid #ddd; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: right; }}
        th {{ background-color: #f2f2f2; }}
       .severity-cell {{ color: white; font-weight: bold; text-align: center; }}
       .payload {{ font-family: 'Courier New', Courier, monospace; background-color: #eee; padding: 2px 5px; border-radius: 3px; direction: ltr; text-align: left; }}
    </style>
    </head><body>
        <h1>تقرير فحص الثغرات لـ: {base_url}</h1>
        <p>تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h2>ملخص النتائج</h2>
        <p>إجمالي الثغرات المكتشفة: {len(vulnerabilities)}</p>
        <h2>تفاصيل الثغرات</h2>
        <table><tr><th>URL المصاب</th><th>نوع الثغرة</th><th>الخطورة</th><th>التفاصيل</th><th>الحمولة المستخدمة</th></tr>
    """
    
    # فرز الثغرات حسب الخطورة
    sorted_vulns = sorted(vulnerabilities, key=lambda x: ["Critical", "High", "Medium", "Low"].index(x.get('severity', 'Low')))
    
    for vuln in sorted_vulns:
        color = severity_colors.get(vuln['severity'], "#fff")
        # استخدام.get() لتجنب الأخطاء إذا كانت بعض الحقول غير موجودة
        url = vuln.get('url', 'N/A')
        vuln_type = vuln.get('type', 'N/A')
        severity = vuln.get('severity', 'N/A')
        details = vuln.get('details', 'N/A')
        payload = vuln.get('payload', 'N/A')
        
        html_content += f"""
            <tr>
                <td>{url}</td>
                <td>{vuln_type}</td>
                <td class="severity-cell" style="background-color:{color};">{severity}</td>
                <td>{details}</td>
                <td class="payload">{payload}</td>
            </tr>
        """
    html_content += "</table></body></html>"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"تم إنشاء التقرير بنجاح: {filename}")
    except IOError as e:
        logging.error(f"فشل إنشاء ملف التقرير: {e}")


