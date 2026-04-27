from flask import Flask, render_template, request, redirect, url_for, flash, abort
import sqlite3, uuid, os
from datetime import datetime

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "forms.db")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change_this_to_a_real_secret")

# 常數表單內容（原本存在 forms 表的資料）
FORM_TITLE = "HITCON CTF 2025 FINAL 冰茶內部報名表單"
FORM_TIME_RANGE = "10/17 ~ 10/18"
FORM_SUBTITLE = ("急需 infra 組在賽前完成 vpn / Attack Manager + Elastic 建置，"
                 "需要自動化完成封包上傳/賽中 jumpbox 出來馬上接進大家的 vpn server 讓大家能直連")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # 只保留 submissions 表
    c.execute("""
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        form_id TEXT,
        email TEXT,
        name TEXT,
        discord_id TEXT,
        primary_skill TEXT,
        secondary_skill TEXT,
        what_can_do TEXT,
        competed_before TEXT,
        onsite_intent TEXT,
        other TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# 啟動時在 app context 初始化 DB
with app.app_context():
    init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/create", methods=["POST", "GET"])
def create_form():
    # 產生 uuid 並回傳可分享的連結（不寫入 DB）
    new_id = uuid.uuid4().hex
    link = "http://xn--hitcon-oz6l6qx86e6k0eu9h.whale-tw.com/form?id=" + new_id
    return render_template("created.html", link=link, formid=new_id)

@app.route("/form", methods=["GET", "POST"])
def form():
    form_id = request.args.get("id", "").strip()
    if not form_id:
        flash("缺少表單 id")
        return redirect(url_for("index"))

    conn = get_db()
    c = conn.cursor()

    # POST: 儲存 submission，然後 redirect 回 GET
    if request.method == "POST":
        data = {
            "email": request.form.get("email","").strip(),
            "name": request.form.get("name","").strip(),
            "discord_id": request.form.get("discord_id","").strip(),
            "primary_skill": request.form.get("primary_skill","").strip(),
            "secondary_skill": request.form.get("secondary_skill","").strip(),
            "what_can_do": request.form.get("what_can_do","").strip(),
            "competed_before": request.form.get("competed_before","").strip(),
            "onsite_intent": request.form.get("onsite_intent","").strip(),
            "other": request.form.get("other","").strip(),
        }
        data["created_at"] = datetime.utcnow().isoformat()

        c.execute("""
        INSERT INTO submissions (
            form_id, email, name, discord_id, primary_skill, secondary_skill,
            what_can_do, competed_before, onsite_intent, other, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            form_id, data["email"], data["name"], data["discord_id"],
            data["primary_skill"], data["secondary_skill"], data["what_can_do"],
            data["competed_before"], data["onsite_intent"], data["other"],
            data["created_at"]
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('form', id=form_id))

    # GET: 檢查是否已有 submission（取最新一筆）
    c.execute(f"SELECT * FROM submissions WHERE form_id = '{form_id}' ORDER BY created_at DESC LIMIT 1")
    submission = c.fetchone()
    if submission:
        data = {
            "email": submission["email"],
            "name": submission["name"],
            "discord_id": submission["discord_id"],
            "primary_skill": submission["primary_skill"],
            "secondary_skill": submission["secondary_skill"],
            "what_can_do": submission["what_can_do"],
            "competed_before": submission["competed_before"],
            "onsite_intent": submission["onsite_intent"],
            "other": submission["other"],
            "created_at": submission["created_at"]
        }
        conn.close()
        return render_template("submitted.html", data=data)

    # 若無 submission，回傳填寫表單（把常數表單內容以 dict 傳入模板）
    conn.close()
    form_info = {
        "id": form_id,
        "title": FORM_TITLE,
        "time_range": FORM_TIME_RANGE,
        "subtitle": FORM_SUBTITLE
    }
    return render_template("form.html", form=form_info)

if __name__ == '__main__':
    # 再確保 DB 已建立（保險）
    init_db()
    app.run(debug=False, host='0.0.0.0', port=2025)

