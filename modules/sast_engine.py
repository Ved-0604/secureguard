import re

RULES = [
    {
        "id": "SG001",
        "name": "Hardcoded Password",
        "pattern": r'(?i)(password|passwd|secret|api_key)\s*=\s*["\'][^"\']{3,}["\']',
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "A02 - Cryptographic Failures",
        "message": "Password is hardcoded directly in source code!",
        "fix": "Use environment variables: os.environ.get('PASSWORD')"
    },
    {
        "id": "SG002",
        "name": "SQL Injection",
        "pattern": r'(?i)(select|insert|update|delete).*["\'].*\+\s*\w',
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03 - Injection",
        "message": "SQL query built with string concatenation — vulnerable to injection!",
        "fix": "Use parameterized queries: cursor.execute('...WHERE id=?', (id,))"
    },
    {
        "id": "SG003",
        "name": "Dangerous eval()",
        "pattern": r'eval\s*\(\s*\w',
        "severity": "HIGH",
        "cwe": "CWE-95",
        "owasp": "A03 - Injection",
        "message": "eval() can execute arbitrary code from user input!",
        "fix": "Remove eval(). Use ast.literal_eval() for safe parsing."
    },
    {
        "id": "SG004",
        "name": "Dangerous exec()",
        "pattern": r'exec\s*\(\s*\w',
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03 - Injection",
        "message": "exec() allows arbitrary code execution — extremely dangerous!",
        "fix": "Never use exec() with user-controlled input."
    },
    {
        "id": "SG005",
        "name": "Command Injection",
        "pattern": r'subprocess\.(call|run|Popen)\s*\(\s*\w',
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03 - Injection",
        "message": "subprocess with user input can lead to OS command injection!",
        "fix": "Use shell=False and sanitize all inputs."
    },
    {
        "id": "SG006",
        "name": "Hardcoded IP Address",
        "pattern": r'["\'](\d{1,3}\.){3}\d{1,3}["\']',
        "severity": "MEDIUM",
        "cwe": "CWE-547",
        "owasp": "A05 - Security Misconfiguration",
        "message": "IP address is hardcoded in source code!",
        "fix": "Use environment variables: os.environ.get('SERVER_IP')"
    },
    {
        "id": "SG007",
        "name": "Weak Hashing Algorithm",
        "pattern": r'(?i)(md5|sha1)\s*\(',
        "severity": "HIGH",
        "cwe": "CWE-327",
        "owasp": "A02 - Cryptographic Failures",
        "message": "MD5/SHA1 are weak and broken hashing algorithms!",
        "fix": "Use bcrypt or sha256 for password hashing."
    },
    {
        "id": "SG008",
        "name": "Debug Mode Enabled",
        "pattern": r'(?i)debug\s*=\s*True',
        "severity": "MEDIUM",
        "cwe": "CWE-94",
        "owasp": "A05 - Security Misconfiguration",
        "message": "Debug mode is enabled — never use in production!",
        "fix": "Set debug=False in production environment."
    },
    {
        "id": "SG009",
        "name": "Insecure Random",
        "pattern": r'random\.(random|randint|choice)\s*\(',
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "owasp": "A02 - Cryptographic Failures",
        "message": "random module is not cryptographically secure!",
        "fix": "Use secrets module: secrets.token_hex()"
    },
    {
        "id": "SG010",
        "name": "XSS - Unescaped Output",
        "pattern": r'render_template_string\s*\(\s*\w',
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03 - Injection",
        "message": "render_template_string can be vulnerable to XSS attacks!",
        "fix": "Use render_template() and escape all user inputs."
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
