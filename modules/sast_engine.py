import re

RULES = [
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
    {
        "id": "SG003",
        "name": "Dangerous eval()",
        "pattern": r'eval\s*\(\s*\w',
        "severity": "HIGH",
        "cwe": "CWE-95",
        "owasp": "A03 - Injection",
        "message": "eval() se user input run ho sakta hai!",
        "fix": "eval() hatao. ast.literal_eval() use karo"
    },
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
    {
        "id": "SG006",
        "name": "Hardcoded IP Address",
        "pattern": r'["\'](\d{1,3}\.){3}\d{1,3}["\']',
        "severity": "MEDIUM",
        "cwe": "CWE-547",
        "owasp": "A05 - Security Misconfiguration",
        "message": "IP address hardcoded hai!",
        "fix": "os.environ.get('SERVER_IP') use karo"
    },
    {
        "id": "SG007",
        "name": "Weak Hashing Algorithm",
        "pattern": r'(?i)(md5|sha1)\s*\(',
        "severity": "HIGH",
        "cwe": "CWE-327",
        "owasp": "A02 - Cryptographic Failures",
        "message": "MD5/SHA1 weak hashing algorithms hain!",
        "fix": "bcrypt ya sha256 use karo passwords ke liye"
    },
    {
        "id": "SG008",
        "name": "Debug Mode Enabled",
        "pattern": r'(?i)debug\s*=\s*True',
        "severity": "MEDIUM",
        "cwe": "CWE-94",
        "owasp": "A05 - Security Misconfiguration",
        "message": "Debug mode production mein ON hai!",
        "fix": "debug=False karo production mein"
    },
    {
        "id": "SG009",
        "name": "Insecure Random",
        "pattern": r'random\.(random|randint|choice)\s*\(',
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "owasp": "A02 - Cryptographic Failures",
        "message": "random module security ke liye safe nahi hai!",
        "fix": "secrets module use karo: secrets.token_hex()"
    },
    {
        "id": "SG010",
        "name": "XSS - Unescaped Output",
        "pattern": r'render_template_string\s*\(\s*\w',
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03 - Injection",
        "message": "render_template_string XSS ke liye vulnerable ho sakta hai!",
        "fix": "render_template() use karo aur input escape karo"
    },
]

def scan_code(source_code):
    findings = []
    lines = source_code.split('\n')
    for rule in RULES:
        matched_lines = []
        for line_num, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line):
                matched_lines.append(line_num)
        if matched_lines:
            findings.append({
                "id":           rule["id"],
                "name":         rule["name"],
                "severity":     rule["severity"],
                "cwe":          rule["cwe"],
                "owasp":        rule["owasp"],
                "message":      rule["message"],
                "fix":          rule["fix"],
                "line_numbers": matched_lines
            })
    return findings
