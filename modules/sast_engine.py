# modules/sast_engine.py
# ==========================================
# MODULE 1 — SAST RULE ENGINE
# Yeh file code ko TEXT ki tarah padh ke
# dangerous patterns dhundhti hai.
# Jaise spell-checker hota hai words ke liye,
# yeh hota hai security bugs ke liye.
# ==========================================

import re   # re = Regular Expressions
            # Isse hum text mein patterns dhundh sakte hain
            # Jaise: "password" word ke baad "=" aur koi string

# ==========================================
# RULES DATABASE
# Har rule ek dictionary hai jisme hai:
#   id       → rule ka unique number
#   name     → vulnerability ka naam
#   pattern  → kya dhundhna hai code mein
#   severity → kitna dangerous hai
#   cwe      → industry standard ID
#   message  → user ko kya batana hai
#   fix      → kaise theek karein
# ==========================================

RULES = [

    # ── RULE 1 ──────────────────────────────
    # Problem: password = "abc123"
    # Kyun bura: Koi bhi jo code padhe woh
    #            password jaan jaata hai!
    # ─────────────────────────────────────────
    {
        "id": "SG001",
        "name": "Hardcoded Password",
        "pattern": r'(?i)(password|passwd|secret|api_key)\s*=\s*["\'][^"\']{3,}["\']',
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "A02 - Cryptographic Failures",
        "message": "Password seedha code mein likha hai!",
        "fix": "os.environ.get('PASSWORD') use karo"
    },

    # ── RULE 2 ──────────────────────────────
    # Problem: query = "SELECT..." + username
    # Kyun bura: Attacker username mein
    #   ' OR '1'='1  daal ke poora DB dekh sakta
    # ─────────────────────────────────────────
    {
        "id": "SG002",
        "name": "SQL Injection",
        "pattern": r'(?i)(select|insert|update|delete).*["\'].*\+\s*\w',
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03 - Injection",
        "message": "SQL query mein string concatenation hai!",
        "fix": "Parameterized queries use karo: cursor.execute('...WHERE id=?', (id,))"
    },

    # ── RULE 3 ──────────────────────────────
    # Problem: eval(user_input)
    # Kyun bura: User jo bhi likhe woh
    #            seedha Python mein run ho jaata!
    # ─────────────────────────────────────────
    {
        "id": "SG003",
        "name": "Dangerous eval()",
        "pattern": r'eval\s*\(\s*\w',
        "severity": "HIGH",
        "cwe": "CWE-95",
        "owasp": "A03 - Injection",
        "message": "eval() se user input run ho sakta hai!",
        "fix": "eval() hatao. ast.literal_eval() use karo safe parsing ke liye"
    },

    # ── RULE 4 ──────────────────────────────
    # Problem: exec(user_data)
    # Kyun bura: eval() se bhi zyada dangerous!
    #            Poore OS commands run ho sakte hain
    # ─────────────────────────────────────────
    {
        "id": "SG004",
        "name": "Dangerous exec()",
        "pattern": r'exec\s*\(\s*\w',
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03 - Injection",
        "message": "exec() se arbitrary code execute ho sakta hai!",
        "fix": "exec() bilkul mat use karo"
    },

    # ── RULE 5 ──────────────────────────────
    # Problem: subprocess.call(user_input)
    # Kyun bura: OS commands directly run ho jaate
    #            Attacker poora server control kar sakta
    # ─────────────────────────────────────────
    {
        "id": "SG005",
        "name": "Command Injection",
        "pattern": r'subprocess\.(call|run|Popen)\s*\(\s*\w',
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03 - Injection",
        "message": "subprocess mein user input OS command injection de sakta hai!",
        "fix": "shell=False rakho aur input sanitize karo"
    },

]


# ==========================================
# MAIN FUNCTION — scan_code()
#
# Yeh function:
# 1. Code string leta hai (jo user paste karta hai)
# 2. Har rule apply karta hai
# 3. Jo bhi match mile, findings list mein daalta hai
# 4. Puri findings list return karta hai
# ==========================================

def scan_code(source_code):
    """
    source_code = wo code string jo user ne paste kiya

    Returns: list of findings
    Har finding ek dict hai:
    {
        "id": "SG001",
        "name": "Hardcoded Password",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "...",
        "message": "...",
        "fix": "...",
        "line_numbers": [2, 5]   ← kaunsi lines pe mila
    }
    """

    findings = []  # Khali list — yahan bugs aayenge

    # Code ko lines mein tod do
    # Taaki line number track kar sakein
    lines = source_code.split('\n')

    # Har rule ke liye loop chalao
    for rule in RULES:

        # Yeh line numbers store karegi
        # jahan yeh rule match hua
        matched_lines = []

        # Har line check karo
        for line_num, line in enumerate(lines, start=1):
            # enumerate start=1 matlab
            # pehli line = line 1 (not 0)

            # re.search = kya yeh pattern
            # is line mein kahin bhi milta hai?
            if re.search(rule["pattern"], line):
                matched_lines.append(line_num)

        # Agar koi line match hui toh
        # finding list mein add karo
        if matched_lines:
            finding = {
                "id":          rule["id"],
                "name":        rule["name"],
                "severity":    rule["severity"],
                "cwe":         rule["cwe"],
                "owasp":       rule["owasp"],
                "message":     rule["message"],
                "fix":         rule["fix"],
                "line_numbers": matched_lines
            }
            findings.append(finding)

    return findings  # Saari findings wapas bhejo


# ==========================================
# TEST SECTION
# Yeh sirf test karne ke liye hai
# Python mein __ name __ == __ main __
# matlab: sirf tab chalao jab yeh file
# seedhi run ho — import pe nahi
# ==========================================

if __name__ == "__main__":

    # Yeh ek deliberately vulnerable code hai
    # Sirf TEST ke liye — real mein aisa mat likho!
    test_code = """
def login(username):
    password = "admin@123"
    query = "SELECT * FROM users WHERE name='" + username + "'"
    eval(user_input)
    db.execute(query)
"""

    print("=" * 50)
    print("SecureGuard — SAST Engine Test")
    print("=" * 50)

    # scan_code function call karo
    results = scan_code(test_code)

    if not results:
        print("Koi vulnerability nahi mili!")
    else:
        print(f"\n{len(results)} vulnerability/ies mili:\n")
        for r in results:
            print(f"[{r['severity']}] {r['name']}")
            print(f"  CWE    : {r['cwe']}")
            print(f"  Lines  : {r['line_numbers']}")
            print(f"  Problem: {r['message']}")
            print(f"  Fix    : {r['fix']}")
            print()