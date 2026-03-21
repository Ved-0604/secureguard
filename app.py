from flask import Flask, render_template, request
import sys
sys.path.insert(0, '.')
from scanner_core import run_scan

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

if __name__ == "__main__":
    app.run(debug=True)
