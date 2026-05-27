import requests
import base64
import hashlib
import re
import io
import time
import json
import threading
import os
from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# --- CONFIGURATION (Hardcoded for Render) ---
PORT = int(os.environ.get("PORT", 3000))
ENCRYPTION_KEY = "nic@impds#dedup05613"
USERNAME = "adminWB"
PASSWORD = "2p3MrgdgV8s9"
BASE_URL = "https://impds.nic.in/impdsdeduplication"

# --- ENCRYPTION HELPER ---
class CryptoHandler:
    def __init__(self, passphrase):
        self.passphrase = passphrase.encode('utf-8')

    def _derive_key_and_iv(self, salt, key_length=32, iv_length=16):
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = hashlib.md5(d_i + self.passphrase + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    def encrypt(self, plain_text):
        from Crypto.Random import get_random_bytes
        salt = get_random_bytes(8)
        key, iv = self._derive_key_and_iv(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
        return base64.b64encode(b"Salted__" + salt + encrypted_bytes).decode('utf-8')

    def decrypt(self, encrypted_b64):
        try:
            encrypted_data = base64.b64decode(encrypted_b64)
            if encrypted_data[:8] != b'Salted__':
                return None
            salt = encrypted_data[8:16]
            cipher_bytes = encrypted_data[16:]
            key, iv = self._derive_key_and_iv(salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return None

crypto_engine = CryptoHandler(ENCRYPTION_KEY)

# --- IMPDS Bot ---
class IMPDSBot:
    def __init__(self):
        self.init_session()
        self.lock = threading.Lock()
        self.jsessionid = None
        self.last_login_time = 0
        self.user_salt = None
        self.csrf_token = None

    def init_session(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/144.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-IN,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': BASE_URL,
            'Referer': f'{BASE_URL}/LoginPage',
            'X-Requested-With': 'XMLHttpRequest',
        })

    def sha512(self, text):
        return hashlib.sha512(text.encode('utf-8')).hexdigest()

    def solve_captcha(self, b64_str):
        """Simple captcha solver - returns dummy for automation"""
        if not b64_str:
            return None
        try:
            img_data = base64.b64decode(b64_str)
            image = Image.open(io.BytesIO(img_data))
            image = image.convert('L')
            image = image.point(lambda x: 0 if x < 145 else 255, '1')
            return "ABCD12"
        except:
            return "ABCD12"

    def perform_login(self):
        try:
            page_headers = self.session.headers.copy()
            if 'X-Requested-With' in page_headers:
                del page_headers['X-Requested-With']
            page_headers['Accept'] = 'text/html,application/xhtml+xml'
            
            r = self.session.get(f"{BASE_URL}/LoginPage", headers=page_headers, timeout=20)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            csrf_input = soup.find('input', {'name': 'REQ_CSRF_TOKEN'})
            self.csrf_token = csrf_input.get('value') if csrf_input else None
            
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and 'USER_SALT' in script.string:
                    match = re.search(r"USER_SALT\s*=\s*['\"]([^'\"]+)['\"]", script.string)
                    if match:
                        self.user_salt = match.group(1)
                        break

            if not self.csrf_token or not self.user_salt:
                return False

            c_res = self.session.post(f"{BASE_URL}/ReloadCaptcha", timeout=10)
            captcha_b64 = c_res.json().get('captchaBase64')
            captcha_text = self.solve_captcha(captcha_b64) or "ABCD12"

            salted_pass = self.sha512(self.sha512(self.user_salt) + self.sha512(PASSWORD))

            payload = {
                'userName': USERNAME,
                'password': salted_pass,
                'captcha': captcha_text,
                'REQ_CSRF_TOKEN': self.csrf_token
            }
            
            post_headers = self.session.headers.copy()
            l_res = self.session.post(f"{BASE_URL}/UserLogin", data=payload, headers=post_headers, timeout=20)
            
            if l_res.status_code == 200:
                try:
                    resp_json = l_res.json()
                    if resp_json.get('athenticationError') == False:
                        self.jsessionid = self.session.cookies.get('JSESSIONID')
                        self.last_login_time = time.time()
                        return True
                except:
                    if "Welcome" in l_res.text or "Dashboard" in l_res.text:
                        self.jsessionid = self.session.cookies.get('JSESSIONID')
                        self.last_login_time = time.time()
                        return True
            return False
        except Exception as e:
            print(f"Login error: {e}")
            return False

    def ensure_session(self):
        with self.lock:
            if self.jsessionid and (time.time() - self.last_login_time < 1200):
                return True
            return self.perform_login()

    def search_aadhaar(self, search_term, encrypted_aadhaar):
        if not self.ensure_session():
            return {"error": "Authentication Failed"}
        
        headers = self.session.headers.copy()
        headers['Referer'] = f"{BASE_URL}/search"
        data = {'search': search_term, 'aadhar': encrypted_aadhaar}
        
        try:
            res = self.session.post(f"{BASE_URL}/search", data=data, headers=headers, timeout=30)
            
            if "LoginPage" in res.text or "UserLogin" in res.text:
                self.jsessionid = None
                if self.ensure_session():
                    res = self.session.post(f"{BASE_URL}/search", data=data, headers=headers, timeout=30)
                else:
                    return {"error": "Re-login failed"}
            
            return self.parse_html(res.text)
        except Exception as e:
            return {"error": str(e)}

    def parse_html(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        tables = soup.find_all('table', class_='table-striped')
        
        if len(tables) < 2:
            return {"error": "No records found"}
        
        main_table = tables[0]
        rows = main_table.find('tbody').find_all('tr') if main_table.find('tbody') else []
        
        if not rows:
            return {"error": "No records found"}
        
        results = []
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 8:
                results.append({
                    "s_no": cols[0].get_text(strip=True),
                    "state": cols[1].get_text(strip=True),
                    "district": cols[2].get_text(strip=True),
                    "ration_card": cols[3].get_text(strip=True),
                    "scheme": cols[4].get_text(strip=True),
                    "member_id": cols[5].get_text(strip=True),
                    "member_name": cols[6].get_text(strip=True),
                    "remark": cols[7].get_text(strip=True)
                })
        
        return results if results else {"error": "No records found"}


bot = IMPDSBot()

# --- Flask Routes ---
@app.route('/search-aadhaar', methods=['GET'])
def api_search():
    search_type = request.args.get('search', 'A')
    aadhaar = request.args.get('aadhaar')
    
    if not aadhaar:
        return jsonify({"success": False, "error": "Missing aadhaar parameter"}), 400
    
    if aadhaar.isdigit() and len(aadhaar) == 12:
        encrypted_val = crypto_engine.encrypt(aadhaar)
    else:
        encrypted_val = aadhaar
    
    result = bot.search_aadhaar(search_type, encrypted_val)
    
    if isinstance(result, dict) and "error" in result:
        return jsonify({"success": False, "error": result["error"]}), 404
    
    return jsonify({"success": True, "count": len(result), "results": result})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "success": True,
        "service": "IMPDS API",
        "session_active": bool(bot.jsessionid)
    })

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "service": "IMPDS Aadhaar to Ration Card API",
        "endpoints": {
            "search": "/search-aadhaar?aadhaar=667168660733",
            "health": "/health"
        }
    })

if __name__ == "__main__":
    print("🚀 IMPDS API starting...")
    bot.ensure_session()
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
