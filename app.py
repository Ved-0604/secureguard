from flask import Flask, render_template, request
import sys
sys.path.insert(0, '.')
from scanner_core import run_scan
from modules.cve_playground import get_all_cves, get_cve_by_id

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    code = ""
    if request.method == "POST":
        code = request.form.get("code", "")
        if code.strip():
            result = run_scan(code)
    return render_template("index.html", result=result, code=code)

@app.route("/cve")
def cve_page():
    cves = get_all_cves()
    return render_template("cve.html", cves=cves)

@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    cve = get_cve_by_id(cve_id)
    if not cve:
        return "CVE not found", 404
    return render_template("cve_detail.html", cve=cve)

if __name__ == "__main__":
    app.run(debug=True)
