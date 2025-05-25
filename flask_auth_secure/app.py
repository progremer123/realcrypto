# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import bcrypt
import smtplib
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DB_FILE = 'users.db'

# 데이터베이스 초기화
def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        # users 테이블
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password BLOB NOT NULL
            )
        ''')

        # sites 테이블
        c.execute('''
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name TEXT NOT NULL,
                login_url TEXT NOT NULL,
                saved_id TEXT,
                saved_pw TEXT
            )
        ''')

        conn.commit()
        conn.close()

init_db()

# 이메일 전송 함수
def send_email(to_email, code):
    from_email = "power700991@gmail.com"  # 발신자 이메일
    from_password = "fzfr dxbx ccqh jpvq"  # 발신자 이메일 비밀번호

    subject = "Your Authentication Code"
    body = f"Your authentication code is: {code}"

    email_text = f"Subject: {subject}\n\n{body}"

    try:
        print("[DEBUG] 이메일 전송 시작")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        print("[DEBUG] SMTP 서버 연결 성공")
        server.login(from_email, from_password)
        print("[DEBUG] SMTP 로그인 성공")
        server.sendmail(from_email, to_email, email_text)
        print("[DEBUG] 이메일 전송 성공")
        server.quit()
    except Exception as e:
        print(f"[ERROR] 이메일 전송 실패: {e}")

# 메인 페이지
@app.route('/')
def index():
    return render_template('index.html')

# 회원가입
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_password))
            conn.commit()
            return '''
                <script>
                    alert("회원가입이 완료되었습니다! 🎉");
                    window.location.href = "/login";
                </script>
            '''
        except sqlite3.IntegrityError:
            return '''
                <script>
                    alert("이미 등록된 이메일입니다. 😢");
                    window.location.href = "/signup";
                </script>
            '''
        finally:
            conn.close()
    return render_template('signup.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT username, password FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user[1]):
            # 인증 코드 생성 및 이메일 전송
            auth_code = random.randint(100000, 999999)
            session['auth_code'] = auth_code
            session['temp_user'] = user[0]
            send_email(email, auth_code)

            return redirect(url_for('verify_code'))
        else:
            return '''
                <script>
                    alert("로그인 실패: 이메일 또는 비밀번호 오류 😢");
                    window.location.href = "/login";
                </script>
            '''
    return render_template('login.html')

# 인증 코드 확인
@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        entered_code = request.form['auth_code']
        if 'auth_code' in session and int(entered_code) == session['auth_code']:
            session.pop('auth_code', None)
            session['username'] = session.pop('temp_user', None)
            return '''
                <script>
                    alert("로그인 성공! 🎉");
                    window.location.href = "/";
                </script>
            '''
        else:
            return '''
                <script>
                    alert("인증 코드가 올바르지 않습니다. 😢");
                    window.location.href = "/verify_code";
                </script>
            '''
    return render_template('verify_code.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))  # 메인 페이지로 이동

# 사이트 목록 보기
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM sites")
    sites = c.fetchall()
    conn.close()
    return render_template('dashboard.html', sites=sites)

# 사이트 추가
@app.route('/add_site', methods=['GET', 'POST'])
def add_site():
    if request.method == 'POST':
        name = request.form['site_name']
        url = request.form['login_url']
        site_id = request.form['saved_id']
        site_pw = request.form['saved_pw']

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO sites (site_name, login_url, saved_id, saved_pw) VALUES (?, ?, ?, ?)",
                  (name, url, site_id, site_pw))
        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    return render_template('add_site.html')

# 서버 실행
if __name__ == '__main__':
    app.run(debug=True)
