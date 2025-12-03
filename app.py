from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import threading
import subprocess
import time
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "super-secret-but-change-if-you-want"

USERNAME = "imranHudaA"
PASSWORD = "Mytestpass@3"

# Global scan state — only 1 scan at a time
SCAN_STATE = {
    "status": "idle",      # idle | running | finished | failed | cancelled
    "message": "",
    "output_file": None,
    "line_count": 0,
    "chunks": 0,
}


def compute_chunks(line_count: int) -> int:
    if line_count <= 10000:
        return 3
    if line_count > 100000:
        return 50

    blocks = (line_count + 9999) // 10000
    return max(6, blocks * 3)


def run_scan(single_domain: str, bulk_file_path: str, is_uploaded_file: bool):
    global SCAN_STATE
    try:
        SCAN_STATE["status"] = "running"
        SCAN_STATE["message"] = "Running clean.sh ..."
        SCAN_STATE["output_file"] = None
        SCAN_STATE["line_count"] = 0
        SCAN_STATE["chunks"] = 0

        os.chdir(BASE_DIR)

        # Determine input for clean.sh
        clean_input = bulk_file_path if bulk_file_path else single_domain.strip()

        # Run clean.sh (always capture safely)
        proc = subprocess.run(
            ["bash", "clean.sh", clean_input],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore"       # IMPORTANT FIX
        )
        print(proc.stdout)

        if proc.returncode != 0:
            SCAN_STATE["status"] = "failed"
            SCAN_STATE["message"] = "clean.sh failed (check logs)"
            return

        # Determine final output file from clean.sh result
        if bulk_file_path:
            first_domain = None
            with open(bulk_file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    d = line.strip()
                    if not d or d.startswith("#"):
                        continue
                    first_domain = d
                    break

            if not first_domain:
                SCAN_STATE["status"] = "failed"
                SCAN_STATE["message"] = "Bulk file had no valid domains."
                return

            output_file = f"{first_domain}.txt"

        else:
            output_file = f"{single_domain.strip()}.txt"

        if not os.path.exists(output_file):
            SCAN_STATE["status"] = "failed"
            SCAN_STATE["message"] = f"Output {output_file} not found."
            return

        # Count lines safely (IMPORTANT FIX)
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for line in f if line.strip())

        SCAN_STATE["output_file"] = output_file
        SCAN_STATE["line_count"] = line_count

        chunks = compute_chunks(line_count)
        SCAN_STATE["chunks"] = chunks
        SCAN_STATE["message"] = f"Running alada.sh with {chunks} chunks ..."

        # Run alada.sh safely
        proc2 = subprocess.run(
            ["bash", "alada.sh", output_file, str(chunks)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore"       # IMPORTANT FIX
        )
        print(proc2.stdout)

        if proc2.returncode != 0:
            SCAN_STATE["status"] = "failed"
            SCAN_STATE["message"] = "alada.sh failed."
            return

        # Clean temporary bulk file
        if bulk_file_path and not is_uploaded_file:
            try:
                os.remove(bulk_file_path)
            except:
                pass

        SCAN_STATE["status"] = "finished"
        SCAN_STATE["message"] = "Scan completed successfully."

    except Exception as e:
        SCAN_STATE["status"] = "failed"
        SCAN_STATE["message"] = f"Error: {str(e)}"


def login_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        if username == USERNAME and password == PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def dashboard():
    return render_template("dashboard.html", scan_state=SCAN_STATE)


@app.route("/start_scan", methods=["POST"])
@login_required
def start_scan():
    global SCAN_STATE

    if SCAN_STATE["status"] == "running":
        flash("A scan is already running. Cancel/reset first.", "error")
        return redirect(url_for("dashboard"))

    domains_text = request.form.get("domains", "").strip()
    uploaded_file = request.files.get("file")

    single_domain = None
    bulk_file_path = None
    is_uploaded_file = False

    if uploaded_file and uploaded_file.filename:
        bulk_file_path = os.path.join(BASE_DIR, "uploaded_domains.txt")
        uploaded_file.save(bulk_file_path)
        is_uploaded_file = True

    elif domains_text:
        lines = [x.strip() for x in domains_text.splitlines() if x.strip()]
        if len(lines) == 1:
            single_domain = lines[0]
        else:
            bulk_file_path = os.path.join(BASE_DIR, "bulk_input.txt")
            with open(bulk_file_path, "w", encoding="utf-8", errors="ignore") as f:
                for l in lines:
                    f.write(l + "\n")

    else:
        flash("Please enter domains or upload file.", "error")
        return redirect(url_for("dashboard"))

    t = threading.Thread(
        target=run_scan,
        args=(single_domain, bulk_file_path, is_uploaded_file),
        daemon=True
    )
    t.start()

    SCAN_STATE["status"] = "running"
    SCAN_STATE["message"] = "Scan started..."

    return redirect(url_for("dashboard"))


@app.route("/results", methods=["GET"])
@login_required
def results():
    results_file = os.path.join(BASE_DIR, "available_results.jsonl")
    rows = []

    if os.path.exists(results_file):
        with open(results_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    rows.append(obj)
                except:
                    pass

    final_rows = {}
    for r in rows:
        domain = r.get("domain")
        if not domain:
            continue
        if domain not in final_rows:
            final_rows[domain] = set()
        for src in r.get("sources", []):
            final_rows[domain].add(src)

    formatted = [{"domain": d, "sources": sorted(list(srcs))} for d, srcs in final_rows.items()]
    formatted.sort(key=lambda x: x["domain"])

    return render_template("results.html", rows=formatted, scan_state=SCAN_STATE)


@app.route("/delete_scan", methods=["POST"])
@login_required
def delete_scan():
    global SCAN_STATE

    if SCAN_STATE["status"] == "running":
        SCAN_STATE["status"] = "cancelled"
        SCAN_STATE["message"] = "Scan cancelled."
    else:
        SCAN_STATE["status"] = "idle"
        SCAN_STATE["message"] = "Scan reset."

    SCAN_STATE["output_file"] = None
    SCAN_STATE["line_count"] = 0
    SCAN_STATE["chunks"] = 0

    # remove files
    for fname in [
        "available_results.jsonl",
        "all_domains.txt",
        "domain_sources.json",
        "bulk_input.txt",
        "uploaded_domains.txt"
    ]:
        fp = os.path.join(BASE_DIR, fname)
        if os.path.exists(fp):
            try:
                os.remove(fp)
            except:
                pass

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=True)
