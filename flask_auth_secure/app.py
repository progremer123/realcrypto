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

# 데이터베이스 초기화 및 테이블 생성
# 중복된 테이블 생성 로직을 통합

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # users 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            otp_method TEXT DEFAULT 'email'
        )
    ''')

    # sites 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_name TEXT NOT NULL,
            login_url TEXT NOT NULL,
            saved_id TEXT,
            saved_pw TEXT
        )
    ''')

    # email_accounts 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

# Flask 애플리케이션 시작 시 데이터베이스 초기화
init_db()

def insert_default_email_account():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        # 기본 이메일 계정 추가
        c.execute("INSERT OR IGNORE INTO email_accounts (email, password) VALUES (?, ?)", 
                  ('test@example.com', 'password123'))
        conn.commit()
        print("[DEBUG] 기본 이메일 계정이 성공적으로 삽입되었습니다.")
    except Exception as e:
        print(f"[ERROR] 기본 이메일 계정 삽입 실패: {e}")
    finally:
        conn.close()

# 초기 이메일 계정 삽입
insert_default_email_account()

# 이메일 전송 함수
def send_email(to_email, code):
    # 송신자 이메일과 비밀번호를 고정 설정
    from_email = 'power700991@gmail.com'  # 송신자 이메일 설정
    from_password = 'xdlctqzgigjzyszc'  # Gmail 앱 비밀번호 설정

    # 디버깅: 송신자 이메일 출력
    print(f"[DEBUG] 송신자 이메일: {from_email}")

    subject = "Your Authentication Code"
    body = f"Your authentication code is: {code}"

    email_text = f"Subject: {subject}\n\n{body}"

    try:
        print("[DEBUG] 이메일 전송 시작")

        # Gmail SMTP 서버 설정
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        print("[DEBUG] SMTP 서버 연결 성공")
        print("[DEBUG] SMTP 로그인 시도 중...")
        server.login(from_email, from_password)
        print("[DEBUG] SMTP 로그인 성공")

        server.sendmail(from_email, to_email, email_text)
        print("[DEBUG] 이메일 전송 성공")
        server.quit()
    except smtplib.SMTPAuthenticationError as e:
        print(f"[ERROR] SMTP 인증 실패: {e}")
    except smtplib.SMTPException as e:
        print(f"[ERROR] SMTP 연결 실패: {e}")
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
        smtp_password = request.form['smtp_password']  # SMTP 비밀번호 추가
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            # 이메일 중복 확인
            c.execute("SELECT email FROM users WHERE email = ?", (email,))
            existing_email = c.fetchone()
            # 디버깅: 입력된 이메일과 데이터베이스 조회 결과 출력
            print(f"[DEBUG] 입력된 이메일: {email}")
            print(f"[DEBUG] 데이터베이스 조회 결과: {existing_email}")
            if existing_email:
                return '''
                    <script>
                        alert("이미 등록된 이메일입니다. 😢");
                        window.location.href = "/signup";
                    </script>
                '''

            # users 테이블에 사용자 정보 저장
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_password))
            # email_accounts 테이블에 SMTP 정보 저장
            c.execute("INSERT INTO email_accounts (email, password) VALUES (?, ?)",
                      (email, smtp_password))
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

# OTP 인증 방식 선택
@app.route('/select_otp_method', methods=['GET', 'POST'])
def select_otp_method():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_method = request.form['otp_method']
        username = session['username']

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET otp_method = ? WHERE username = ?", (otp_method, username))
        conn.commit()
        conn.close()

        return '''
            <script>
                alert("인증 방식이 저장되었습니다! 🎉");
                window.location.href = "/dashboard";
            </script>
        '''

    return render_template('select_otp_method.html')

# 회원탈퇴
@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = session['username']

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            # users 테이블에서 사용자 삭제
            c.execute("DELETE FROM users WHERE username = ?", (username,))
            # email_accounts 테이블에서도 관련 이메일 삭제 (선택 사항)
            c.execute("DELETE FROM email_accounts WHERE email = (SELECT email FROM users WHERE username = ?)", (username,))
            conn.commit()
            session.pop('username', None)
            return '''
                <script>
                    alert("회원탈퇴가 완료되었습니다. 😢");
                    window.location.href = "/";
                </script>
            '''
        except Exception as e:
            print(f"[ERROR] 회원탈퇴 실패: {e}")
            return '''
                <script>
                    alert("회원탈퇴 중 문제가 발생했습니다. 😢");
                    window.location.href = "/dashboard";
                </script>
            '''
        finally:
            conn.close()

    return render_template('delete_account.html')

# 서버 실행
if __name__ == '__main__':
    app.run(debug=True)
