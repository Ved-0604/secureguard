import sys
sys.path.insert(0, '.')
from modules.sast_engine import scan_code

def calculate_risk_score(findings):
    weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    total = sum(weights.get(f["severity"], 5) for f in findings)
    score = min(total, 100)
    if score >= 70:
        level = "CRITICAL RISK"
    elif score >= 40:
        level = "HIGH RISK"
    elif score >= 10:
        level = "MEDIUM RISK"
    else:
        level = "SAFE"
    return {
        "score": score,
        "level": level,
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
    }

test_code = """
def login(username):
    password = "admin@123"
    query = "SELECT * FROM users WHERE name='" + username + "'"
    eval(user_input)
"""

findings = scan_code(test_code)
result = calculate_risk_score(findings)
print("=" * 40)
print("Risk Score Report")
print("=" * 40)
print(f"Score   : {result['score']} / 100")
print(f"Level   : {result['level']}")
print(f"Total   : {result['total_findings']} findings")
print(f"CRITICAL: {result['critical']}")
print(f"HIGH    : {result['high']}")
print(f"MEDIUM  : {result['medium']}")
