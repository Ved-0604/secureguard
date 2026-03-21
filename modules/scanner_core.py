cat > scanner_core.py << 'EOF'
import sys
sys.path.insert(0, '.')
from modules.sast_engine import scan_code
from modules.ai_reviewer import ai_review
from modules.risk_scorer import calculate_risk_score

def run_scan(code):
    findings = scan_code(code)
    risk = calculate_risk_score(findings)
    ai_result = ai_review(code, findings)
    return {
        "findings": findings,
        "risk": risk,
        "explanation": ai_result["explanation"],
        "fixed_code": ai_result["fixed_code"]
    }
EOF