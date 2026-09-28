from flask import Flask, render_template, request, redirect, session, Response
from flask_mysqldb import MySQL
from reportlab.pdfgen import canvas
import io
import os

# ---------------- APP CONFIG ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = "mysql2027system"
import os

print("APP FILE =", __file__)
print("BASE_DIR =", BASE_DIR)
print("TEMPLATES PATH =", app.template_folder)
print("FILES =", os.listdir(app.template_folder))

# ---------------- MYSQL CONFIG ----------------

app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "mysql2027system"
app.config["MYSQL_DB"] = "cyber_threat"

mysql = MySQL(app)

# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("home.html")

# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()

        cur.execute(
            "INSERT INTO users(username,email,password) VALUES(%s,%s,%s)",
            (username, email, password)
        )

        mysql.connection.commit()
        cur.close()

        return redirect("/login")

    return render_template("register.html")

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT * FROM users WHERE email=%s AND password=%s",
            (email, password)
        )

        user = cur.fetchone()
        cur.close()

        if user:
            session["user"] = user[1]
            return redirect("/dashboard")

        return "Invalid Login"

    return render_template("login.html")

# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    cur = mysql.connection.cursor()

    # Total scans
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE username=%s",
                (session["user"],))
    total_scans = cur.fetchone()[0]

    # High Risk
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE username=%s AND risk_score >= 70",
                (session["user"],))
    high_count = cur.fetchone()[0]

    # Medium Risk
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE username=%s AND risk_score >= 40 AND risk_score < 70",
                (session["user"],))
    medium_count = cur.fetchone()[0]

    # Safe Results
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE username=%s AND risk_score < 40",
                (session["user"],))
    safe_count = cur.fetchone()[0]

    # Recent History
    cur.execute("""
        SELECT * FROM scan_history
        WHERE username=%s
        ORDER BY scanned_at DESC
        LIMIT 5
    """, (session["user"],))

    history = cur.fetchall()

    cur.close()

    return render_template(
        "dashboard.html",
        username=session["user"],
        total_scans=total_scans,
        high_count=high_count,
        medium_count=medium_count,
        safe_count=safe_count,
        history=history
    )
# ---------------- SCAN ----------------

@app.route("/scan", methods=["POST"])
def scan():

    if "user" not in session:
        return redirect("/login")

    input_data = request.form["input_data"]

    threat_type = "Safe"
    risk_score = 20
    action = "No Action Needed"

    text = input_data.lower()

    if "http" in text or "www" in text:
        threat_type = "Suspicious URL"
        risk_score = 85
        action = "Block URL"

    elif "192." in text or "10." in text:
        threat_type = "Suspicious IP"
        risk_score = 70
        action = "Block IP"

    elif "password" in text or "otp" in text:
        threat_type = "Phishing Message"
        risk_score = 80
        action = "Alert User"

    cur = mysql.connection.cursor()

    cur.execute(
        """INSERT INTO scan_history
        (username,input_data,threat_type,risk_score,action)
        VALUES(%s,%s,%s,%s,%s)""",
        (
            session["user"],
            input_data,
            threat_type,
            risk_score,
            action
        )
    )

    mysql.connection.commit()
    cur.close()

    return redirect("/dashboard")

# ---------------- HISTORY ----------------

@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/login")

    cur = mysql.connection.cursor()

    cur.execute(
        """SELECT input_data, threat_type, risk_score, scanned_at
        FROM scan_history
        WHERE username=%s
        ORDER BY scanned_at DESC""",
        (session["user"],)
    )

    history = cur.fetchall()
    cur.close()

    return render_template(
        "history.html",
        history=history
    )

# ---------------- ANALYTICS ----------------

@app.route("/analytics")
def analytics():

    if "user" not in session:
        return redirect("/login")

    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT COUNT(*) FROM scan_history WHERE username=%s",
        (session["user"],)
    )
    total_scans = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM scan_history WHERE username=%s AND risk_score>=70",
        (session["user"],)
    )
    high_count = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM scan_history WHERE username=%s AND risk_score>=40 AND risk_score<70",
        (session["user"],)
    )
    medium_count = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM scan_history WHERE username=%s AND risk_score<40",
        (session["user"],)
    )
    safe_count = cur.fetchone()[0]

    cur.close()

    return render_template(
        "analytics.html",
        total_scans=total_scans,
        high_count=high_count,
        medium_count=medium_count,
        safe_count=safe_count
    )

# ---------------- ADMIN ----------------

@app.route("/admin")
def admin():

    if "user" not in session:
        return redirect("/login")

    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT username, input_data, threat_type, risk_score, scanned_at
        FROM scan_history
        ORDER BY scanned_at DESC
    """)

    history = cur.fetchall()
    cur.close()

    return render_template("admin.html", history=history)
# ---------------- PDF REPORT ----------------

@app.route("/download_report")
def download_report():

    if "user" not in session:
        return redirect("/login")

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer)

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(180, 800, "Cyber Threat Detection Report")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, 770, "User : " + session["user"])

    cur = mysql.connection.cursor()

    cur.execute(
        """SELECT input_data,threat_type,risk_score
        FROM scan_history
        WHERE username=%s
        ORDER BY scanned_at DESC""",
        (session["user"],)
    )

    data = cur.fetchall()
    cur.close()

    y = 730

    for row in data:

        pdf.drawString(40, y, f"Input : {row[0]}")
        y -= 20

        pdf.drawString(40, y, f"Threat : {row[1]}")
        y -= 20

        pdf.drawString(40, y, f"Risk Score : {row[2]}")
        y -= 30

        if y < 80:
            pdf.showPage()
            y = 750

    pdf.save()

    buffer.seek(0)

    return Response(
        buffer,
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
            "attachment;filename=Cyber_Report.pdf"
        }
    )

# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
@app.route("/delete/<int:id>")
def delete(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM scan_history WHERE id=%s",(id,))
    mysql.connection.commit()
    cur.close()
    return redirect("/admin")

# ---------------- RUN APP ----------------

if __name__ == "__main__":
    app.run(debug=True)