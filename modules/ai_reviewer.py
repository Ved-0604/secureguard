# modules/ai_reviewer.py

import requests
import os

def ai_review(code, findings):

    if not findings:
        return {
            "explanation": "Koi vulnerability nahi mili!",
            "fixed_code": code
        }

    findings_text = ""
    for f in findings:
        findings_text += f"- {f['name']} ({f['severity']}) - {f['message']}\n"

    prompt = f"""You are a cybersecurity expert. 

Code has these vulnerabilities:
{findings_text}

Vulnerable code:
{code}

Respond EXACTLY in this format:
EXPLANATION:
[2-3 sentences explaining why dangerous]

FIXED_CODE:
[complete fixed secure code]
"""

    API_URL = "https://router.huggingface.co/novita/v3/openai/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {os.environ.get('HF_API_KEY')}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "meta-llama/llama-3.1-8b-instruct",
        "messages": [
            {
                "role": "user", 
                "content": prompt
            }
        ],
        "max_tokens": 1024,
        "temperature": 0.3
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        data = response.json()
        
        # Response se text nikalo
        response_text = data["choices"][0]["message"]["content"]
        
        explanation = ""
        fixed_code = ""
        current_section = None

        for line in response_text.split('\n'):
            if line.startswith("EXPLANATION:"):
                current_section = "explanation"
            elif line.startswith("FIXED_CODE:"):
                current_section = "fixed_code"
            elif current_section == "explanation":
                explanation += line + "\n"
            elif current_section == "fixed_code":
                fixed_code += line + "\n"

        return {
            "explanation": explanation.strip() or response_text[:300],
            "fixed_code": fixed_code.strip() or "# See explanation above"
        }

    except Exception as e:
        print(f"AI error: {e}")
        return fallback_review(findings)


def fallback_review(findings):
    explanations = []
    for f in findings:
        if f['cwe'] == 'CWE-798':
            explanations.append(
                "Hardcoded password! Anyone with code "
                "access can steal this credential."
            )
        elif f['cwe'] == 'CWE-89':
            explanations.append(
                "SQL Injection! Attacker can access "
                "entire database."
            )
        elif f['cwe'] == 'CWE-95':
            explanations.append(
                "Dangerous eval()! Attacker can run "
                "arbitrary code on server."
            )
        else:
            explanations.append(f["message"])

    return {
        "explanation": " | ".join(explanations),
        "fixed_code": "# Fix the vulnerabilities listed above."
    }


if __name__ == "__main__":
    import sys
    sys.path.insert(0, '.')
    from modules.sast_engine import scan_code

    test_code = """
def login(username):
    password = "admin@123"
    query = "SELECT * FROM users WHERE name='" + username + "'"
    eval(user_input)
    db.execute(query)
"""

    print("=" * 50)
    print("SecureGuard — AI Reviewer Test")
    print("=" * 50)

    findings = scan_code(test_code)
    print(f"\nSAST ne {len(findings)} bugs pakde\n")
    print("AI se review ho raha hai...\n")

    result = ai_review(test_code, findings)

    print("--- AI EXPLANATION ---")
    print(result["explanation"])
    print("\n--- FIXED CODE ---")
    print(result["fixed_code"])