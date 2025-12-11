from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from functools import wraps
import os
import re
import time
import hashlib
import json
import logging
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Logging ayarı
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# ========== GÜVENLİK AYARLARI ==========

# 1. Rate Limiting (DDoS koruması)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True
)

# 2. Security Headers & CSP
csp = {
    'default-src': "'self'",
    'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    'script-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'base-uri': "'self'",
    'form-action': "'self'"
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    force_https=bool(os.environ.get('FORCE_HTTPS', True)),
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite='Lax',
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
    permissions_policy={
        'accelerometer': '()',
        'camera': '()',
        'geolocation': '()',
        'microphone': '()',
        'payment': '()'
    }
)

# 3. Request Rate Limiter (IP bazlı)
class RateLimiter:
    def __init__(self):
        self.requests = {}
        self.cleanup_interval = 300  # 5 dakika
        self.last_cleanup = time.time()
    
    def is_allowed(self, ip, limit=100, window=60):
        current_time = time.time()
        
        # Eski kayıtları temizle
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_requests(current_time)
            self.last_cleanup = current_time
        
        if ip not in self.requests:
            self.requests[ip] = []
        
        # Pencere içindeki request'leri filtrele
        window_start = current_time - window
        self.requests[ip] = [req_time for req_time in self.requests[ip] if req_time > window_start]
        
        if len(self.requests[ip]) >= limit:
            return False
        
        self.requests[ip].append(current_time)
        return True
    
    def _cleanup_old_requests(self, current_time, max_age=3600):
        """1 saatten eski kayıtları temizle"""
        for ip in list(self.requests.keys()):
            self.requests[ip] = [req_time for req_time in self.requests[ip] 
                               if current_time - req_time < max_age]
            if not self.requests[ip]:
                del self.requests[ip]

rate_limiter = RateLimiter()

# 4. SQL Injection & XSS koruması
def sanitize_input(input_string, max_length=500):
    """Giriş verilerini temizle ve doğrula"""
    if not input_string:
        return ""
    
    # Uzunluk kontrolü
    if len(input_string) > max_length:
        input_string = input_string[:max_length]
    
    # SQL Injection pattern'leri
    sql_patterns = [
        (r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER|CREATE|TRUNCATE)\b)', '[SQL_BLOCKED]'),
        (r'(\b(OR|AND)\b\s+\d+\s*=\s*\d+)', '[LOGIC_BLOCKED]'),
        (r'(\-\-|\#|\/\*|\*\/|;)', '[COMMENT_BLOCKED]'),
        (r'(\b(WAITFOR|DELAY|SLEEP|BENCHMARK)\b)', '[DELAY_BLOCKED]'),
        (r'(\b(CHAR|CONCAT|SUBSTRING|CAST|CONVERT)\b\s*\()', '[FUNC_BLOCKED]'),
        (r'(@@|LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)', '[FILE_BLOCKED]'),
        (r'(\b(SCRIPT|JAVASCRIPT|ON\w+)\b)', '[SCRIPT_BLOCKED]')
    ]
    
    cleaned = str(input_string)
    
    for pattern, replacement in sql_patterns:
        cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
    
    # HTML escape
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
        ">": "&gt;",
        "<": "&lt;",
        "/": "&#x2F;",
        "`": "&#96;",
        "=": "&#61;"
    }
    
    for char, escape in html_escape_table.items():
        cleaned = cleaned.replace(char, escape)
    
    return cleaned.strip()

# 5. User-Agent & Bot kontrolü
def validate_request(request):
    """Request'i doğrula ve güvenlik kontrolleri yap"""
    
    # IP rate limiting
    ip = request.remote_addr
    if not rate_limiter.is_allowed(ip, limit=150, window=60):
        logger.warning(f"Rate limit exceeded for IP: {ip}")
        return False
    
    # User-Agent kontrolü
    user_agent = request.user_agent.string or ""
    if not user_agent:
        logger.warning(f"No User-Agent from IP: {ip}")
        return False
    
    # Kötü niyetli botlar
    bad_agents = [
        'sqlmap', 'nikto', 'wget', 'curl', 'python-requests',
        'nmap', 'nessus', 'metasploit', 'hydra', 'burpsuite',
        'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'arachni',
        'acunetix', 'netsparker', 'appscan', 'zap', 'w3af'
    ]
    
    ua_lower = user_agent.lower()
    for bad in bad_agents:
        if bad in ua_lower:
            logger.warning(f"Bad User-Agent detected from IP: {ip} - Agent: {user_agent}")
            return False
    
    # Referer kontrolü (CSRF koruması)
    if request.method == 'POST':
        referer = request.headers.get('Referer', '')
        if referer and not referer.startswith(request.host_url):
            logger.warning(f"Suspicious Referer from IP: {ip} - Referer: {referer}")
            return False
    
    return True

# 6. Decorator'lar
def security_check(f):
    """Tüm güvenlik kontrollerini uygula"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Request doğrulama
            if not validate_request(request):
                abort(429)  # Too Many Requests
            
            # POST request'leri için ek kontroller
            if request.method in ['POST', 'PUT']:
                # Content-Length kontrolü
                content_length = request.content_length or 0
                if content_length > 10 * 1024 * 1024:  # 10MB limit
                    abort(413)  # Payload Too Large
                
                # Content-Type kontrolü
                if request.content_type and 'multipart/form-data' in request.content_type:
                    abort(415)  # Unsupported Media Type
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Security check failed: {str(e)}")
            abort(403)
    
    return decorated_function

def vip_required(f):
    """VIP giriş kontrolü"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'vip_logged_in' not in session or not session.get('vip_logged_in'):
            return redirect(url_for('vip_giris'))
        
        # Session timeout kontrolü (30 dakika)
        login_time = session.get('login_time')
        if login_time:
            login_dt = datetime.fromisoformat(login_time)
            if datetime.now() - login_dt > timedelta(minutes=30):
                session.clear()
                return redirect(url_for('vip_giris'))
        
        return f(*args, **kwargs)
    return decorated_function

# ========== GÜVENLİK FONKSİYONLARI ==========

def hash_password(password):
    """Şifreyi güvenli hash'le"""
    salt = os.urandom(32).hex()
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000,
        dklen=128
    )
    return f"{salt}${key.hex()}"

def verify_password(stored_hash, password):
    """Hash'lenmiş şifreyi doğrula"""
    try:
        salt, key = stored_hash.split('$')
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=128
        )
        return key == new_key.hex()
    except:
        return False

def generate_csrf_token():
    """CSRF token oluştur"""
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(32).hex()
    return session['csrf_token']

def verify_csrf_token(token):
    """CSRF token doğrula"""
    return token == session.get('csrf_token')

# ========== API LİSTELERİ ==========

FREE_APIS = [
    {"name": "Ad Soyad TC", "endpoint": "https://nabiscapi-m6ii.onrender.com/tc?tc=", "desc": "TC'den ad soyad sorgulama"},
    {"name": "TC GSM", "endpoint": "https://nabiscapi-m6ii.onrender.com/tcgsm?tc=", "desc": "TC'den telefon sorgulama"},
    {"name": "GSM TC", "endpoint": "https://nabiscapi-m6ii.onrender.com/gsmtc?gsm=", "desc": "Telefondan TC sorgulama"},
    {"name": "Adres", "endpoint": "https://nabiscapi-m6ii.onrender.com/adres?tc=", "desc": "TC'den adres sorgulama"},
    {"name": "Yabancı Sülale", "endpoint": "https://nabiscapi-m6ii.onrender.com/yabanci?ad=&soyad=", "desc": "Yabancı kişi sorgulama"},
    {"name": "Baba", "endpoint": "https://nabiscapi-m6ii.onrender.com/baba?tc=", "desc": "Baba bilgileri"},
    {"name": "Anne", "endpoint": "https://nabiscapi-m6ii.onrender.com/anne?tc=", "desc": "Anne bilgileri"},
    {"name": "Yetimlik", "endpoint": "https://nabiscapi-m6ii.onrender.com/yetimlik?babatc=", "desc": "Yetimlik sorgulama"}
]

VIP_APIS = [
    {"name": "Cinsiyet", "endpoint": "https://nabiscapi-m6ii.onrender.com/cinsiyet?tc=", "desc": "TC'den cinsiyet"},
    {"name": "Din", "endpoint": "https://nabiscapi-m6ii.onrender.com/din?tc=", "desc": "TC'den din sorgulama"},
    {"name": "Burç", "endpoint": "https://nabiscapi-m6ii.onrender.com/burc?tc=", "desc": "TC'den burç"},
    {"name": "Köy", "endpoint": "https://nabiscapi-m6ii.onrender.com/koy?tc=", "desc": "TC'den köy bilgisi"},
    {"name": "Vergi No", "endpoint": "https://nabiscapi-m6ii.onrender.com/vergino?tc=", "desc": "TC'den vergi numarası"},
    {"name": "Medeni Hal", "endpoint": "https://nabiscapi-m6ii.onrender.com/medenihal?tc=", "desc": "TC'den medeni hal"},
    {"name": "Kimlik Kayıt", "endpoint": "https://nabiscapi-m6ii.onrender.com/kimlikkayit?tc=", "desc": "Kimlik kayıt yeri"},
    {"name": "Doğum Yeri", "endpoint": "https://nabiscapi-m6ii.onrender.com/dogumyeri?tc=", "desc": "TC'den doğum yeri"},
    {"name": "Vesika", "endpoint": "https://nabiscapi-m6ii.onrender.com/vesika?tc=", "desc": "Kimlik vesikası"},
    {"name": "İşyeri Sektörü", "endpoint": "https://nabiscapi-m6ii.onrender.com/isyeriSektoru?ad=&soyad=&tc=", "desc": "İşyeri sektörü"},
    {"name": "İşe Giriş Tarihi", "endpoint": "https://nabiscapi-m6ii.onrender.com/iseGirisTarihi?ad=&soyad=&tc=", "desc": "İşe başlama tarihi"},
    {"name": "İşyeri Ünvanı", "endpoint": "https://nabiscapi-m6ii.onrender.com/isyeriUnvani?ad=&soyad=&tc=", "desc": "İşyeri adı"},
    {"name": "Güncel Adres", "endpoint": "https://nabiscapi-m6ii.onrender.com/guncelAdres?ad=&soyad=&tc=", "desc": "Güncel adres"},
    {"name": "TC Plaka", "endpoint": "https://nabiscapi-m6ii.onrender.com/tcplaka?tc=", "desc": "TC'den plaka"},
    {"name": "TC Yeni", "endpoint": "https://nabiscapi-m6ii.onrender.com/tcyeni?tc=", "desc": "Yeni TC sorgulama"},
    {"name": "Ad Yeni", "endpoint": "https://nabiscapi-m6ii.onrender.com/adyeni?ad=&soyad=", "desc": "Ad soyad sorgulama"},
    {"name": "GSM Yeni", "endpoint": "https://nabiscapi-m6ii.onrender.com/gsmyeni?gsm=", "desc": "Yeni GSM sorgulama"},
    {"name": "Kardeş", "endpoint": "https://nabiscapi-m6ii.onrender.com/kardes?tc=", "desc": "Kardeş bilgileri"},
    {"name": "Çocuklar", "endpoint": "https://nabiscapi-m6ii.onrender.com/cocuklar?tc=", "desc": "Çocuk bilgileri"},
    {"name": "Çocuk", "endpoint": "https://nabiscapi-m6ii.onrender.com/cocuk?tc=", "desc": "Çocuk bilgisi"},
    {"name": "Amca", "endpoint": "https://nabiscapi-m6ii.onrender.com/amca?tc=", "desc": "Amca bilgileri"},
    {"name": "Dayı", "endpoint": "https://nabiscapi-m6ii.onrender.com/dayi?tc=", "desc": "Dayı bilgileri"},
    {"name": "Hala", "endpoint": "https://nabiscapi-m6ii.onrender.com/hala?tc=", "desc": "Hala bilgileri"},
    {"name": "Teyze", "endpoint": "https://nabiscapi-m6ii.onrender.com/teyze?tc=", "desc": "Teyze bilgileri"},
    {"name": "Kuzen", "endpoint": "https://nabiscapi-m6ii.onrender.com/kuzen?tc=", "desc": "Kuzen bilgileri"},
    {"name": "Dede", "endpoint": "https://nabiscapi-m6ii.onrender.com/dede?tc=", "desc": "Dede bilgileri"},
    {"name": "Nine", "endpoint": "https://nabiscapi-m6ii.onrender.com/nine?tc=", "desc": "Nine bilgileri"},
    {"name": "Yeniden", "endpoint": "https://nabiscapi-m6ii.onrender.com/yeniden?tc=", "desc": "Yeniden sorgulama"},
    {"name": "Sorgu", "endpoint": "https://nabiscapi-m6ii.onrender.com/sorgu?ad=&soyad=", "desc": "Ad soyad sorgulama"},
    {"name": "Aile", "endpoint": "https://nabiscapi-m6ii.onrender.com/aile?tc=", "desc": "Aile bilgileri"},
    {"name": "Sülale", "endpoint": "https://nabiscapi-m6ii.onrender.com/sulale?tc=", "desc": "Sülale bilgileri"},
    {"name": "Ölüm Tarihi", "endpoint": "https://nabiscapi-m6ii.onrender.com/olumtarihi?tc=", "desc": "Ölüm tarihi"},
    {"name": "SMS", "endpoint": "https://nabiscapi-m6ii.onrender.com/sms?gsm=", "desc": "SMS bilgileri"},
    {"name": "Kızlık Soyad", "endpoint": "https://nabiscapi-m6ii.onrender.com/kizliksoyad?tc=", "desc": "Kızlık soyadı"},
    {"name": "Yaş", "endpoint": "https://nabiscapi-m6ii.onrender.com/yas?tc=", "desc": "TC'den yaş"},
    {"name": "Hikaye", "endpoint": "https://nabiscapi-m6ii.onrender.com/hikaye?tc=", "desc": "TC hikayesi"},
    {"name": "Sıra No", "endpoint": "https://nabiscapi-m6ii.onrender.com/sirano?tc=", "desc": "Sıra numarası"},
    {"name": "Ayak No", "endpoint": "https://nabiscapi-m6ii.onrender.com/ayakno?tc=", "desc": "Ayak numarası"},
    {"name": "Operatör", "endpoint": "https://nabiscapi-m6ii.onrender.com/operator?gsm=", "desc": "GSM operatörü"},
    {"name": "Yeğen", "endpoint": "https://nabiscapi-m6ii.onrender.com/yegen?tc=", "desc": "Yeğen bilgileri"},
    {"name": "RAW", "endpoint": "https://nabiscapi-m6ii.onrender.com/raw?tc=", "desc": "Ham veri"},
    {"name": "IBAN Doğrulama", "endpoint": "https://nabiscapi-m6ii.onrender.com/iban_dogrulama?iban=", "desc": "IBAN doğrulama"},
    {"name": "IBAN Sorgulama", "endpoint": "https://nabiscapi-m6ii.onrender.com/iban_sorgulama?iban=", "desc": "IBAN sorgulama"},
    {"name": "Sağlık", "endpoint": "https://nabiscapi-m6ii.onrender.com/saglik", "desc": "Sağlık bilgileri"}
]

# ========== VIP KULLANICI VERİTABANI ==========
class VIPDatabase:
    def __init__(self):
        self.users = {
            "admin": {
                "password_hash": hash_password("admin123"),
                "vip_key": "NABI-VIP-2024",
                "created_at": datetime.now(),
                "last_login": None,
                "is_active": True
            }
        }
    
    def add_user(self, username, password, vip_key):
        """Yeni VIP kullanıcı ekle"""
        if username in self.users:
            return False
        
        self.users[username] = {
            "password_hash": hash_password(password),
            "vip_key": vip_key,
            "created_at": datetime.now(),
            "last_login": None,
            "is_active": True
        }
        return True
    
    def verify_user(self, username, password, vip_key):
        """Kullanıcı doğrula"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        
        if not user["is_active"]:
            return False
        
        if user["vip_key"] != vip_key:
            return False
        
        if not verify_password(user["password_hash"], password):
            return False
        
        # Son giriş tarihini güncelle
        user["last_login"] = datetime.now()
        return True

vip_db = VIPDatabase()

# ========== ROUTES ==========

@app.route('/')
@limiter.limit("100 per hour")
@security_check
def anasayfa():
    """Ana sayfa"""
    # CSRF token oluştur
    csrf_token = generate_csrf_token()
    response = make_response(render_template(
        'anasayfa.html',
        free_apis=FREE_APIS,
        vip_apis=VIP_APIS,
        vip_count=len(VIP_APIS),
        csrf_token=csrf_token
    ))
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

@app.route('/vip_giris', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@security_check
def vip_giris():
    """VIP giriş sayfası"""
    if request.method == 'POST':
        try:
            # CSRF token kontrolü
            csrf_token = request.form.get('csrf_token')
            if not verify_csrf_token(csrf_token):
                logger.warning("CSRF token validation failed")
                abort(403)
            
            # Input sanitization
            username = sanitize_input(request.form.get('username', ''))
            password = request.form.get('password', '')
            vip_key = sanitize_input(request.form.get('vip_key', ''))
            
            # Kullanıcı doğrulama
            if vip_db.verify_user(username, password, vip_key):
                # Session oluştur
                session['vip_logged_in'] = True
                session['vip_username'] = username
                session['login_time'] = datetime.now().isoformat()
                session['user_agent'] = request.user_agent.string
                session['ip_address'] = request.remote_addr
                
                # Session ID'yi yenile
                session.permanent = True
                
                logger.info(f"VIP user logged in: {username} from {request.remote_addr}")
                return redirect(url_for('vip_api'))
            else:
                logger.warning(f"Failed login attempt for username: {username} from {request.remote_addr}")
                return render_template('vipgiris.html', 
                                     error="Geçersiz kullanıcı adı, şifre veya VIP anahtarı!",
                                     csrf_token=generate_csrf_token())
        
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            abort(500)
    
    # GET request için
    return render_template('vipgiris.html', csrf_token=generate_csrf_token())

@app.route('/vip_api')
@vip_required
@limiter.limit("200 per hour")
@security_check
def vip_api():
    """VIP API sayfası"""
    # Kullanıcı bilgilerini al
    username = session.get('vip_username', 'Kullanıcı')
    login_time = session.get('login_time')
    
    if login_time:
        login_dt = datetime.fromisoformat(login_time)
        session_time = (datetime.now() - login_dt).seconds // 60  # dakika
    
    # API'leri kategorilere göre grupla
    categories = {}
    for api in VIP_APIS:
        category = "Premium"
        if any(word in api['desc'].lower() for word in ['aile', 'baba', 'anne', 'kardeş']):
            category = "Aile"
        elif any(word in api['desc'].lower() for word in ['iş', 'işyeri', 'çalışma']):
            category = "İş"
        elif any(word in api['desc'].lower() for word in ['iban', 'finans']):
            category = "Finans"
        elif any(word in api['desc'].lower() for word in ['sağlık']):
            category = "Sağlık"
        
        if category not in categories:
            categories[category] = []
        categories[category].append(api)
    
    response = make_response(render_template(
        'vipapi.html',
        apis=VIP_APIS,
        categories=categories,
        username=username,
        login_time=login_time,
        csrf_token=generate_csrf_token()
    ))
    
    return response

@app.route('/satin_al')
@limiter.limit("50 per hour")
@security_check
def satin_al():
    """Satın alma sayfası"""
    return render_template('satinal.html', csrf_token=generate_csrf_token())

@app.route('/cikis')
@security_check
def cikis():
    """Çıkış yap"""
    username = session.get('vip_username', 'Unknown')
    logger.info(f"User logged out: {username}")
    
    # Session'ı temizle
    session.clear()
    
    # Cookie'leri geçersiz kıl
    response = make_response(redirect(url_for('anasayfa')))
    response.set_cookie('session', '', expires=0)
    
    return response

@app.route('/api_test/<api_name>')
@vip_required
@limiter.limit("30 per minute")
@security_check
def api_test(api_name):
    """API test endpoint'i (sadece VIP)"""
    api_name = sanitize_input(api_name)
    
    # API'yi bul
    api = next((a for a in VIP_APIS if a['name'] == api_name), None)
    if not api:
        abort(404)
    
    # Log kaydı
    logger.info(f"API test by {session.get('vip_username')}: {api_name}")
    
    return jsonify({
        "status": "success",
        "api": api['name'],
        "endpoint": api['endpoint'],
        "message": "API test için hazır",
        "example": api['endpoint'] + '12345678901'
    })

@app.route('/favicon.ico')
def favicon():
    """Favicon için boş response"""
    response = make_response('', 204)
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

# ========== HEALTH CHECK ==========
@app.route('/health')
def health_check():
    """Health check endpoint (Render için)"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "Nabi System API",
        "version": "2.0.0"
    })

# ========== ERROR HANDLERS ==========
@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html',
                         error_code=400,
                         error_message="Geçersiz istek!"), 400

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html',
                         error_code=403,
                         error_message="Erişim engellendi!"), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html',
                         error_code=404,
                         error_message="Sayfa bulunamadı!"), 404

@app.errorhandler(429)
def ratelimit_error(error):
    return render_template('error.html',
                         error_code=429,
                         error_message="Çok fazla istek! Lütfen bekleyin."), 429

@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {str(error)}")
    return render_template('error.html',
                         error_code=500,
                         error_message="Sunucu hatası! Lütfen daha sonra tekrar deneyin."), 500

# ========== AFTER REQUEST ==========
@app.after_request
def add_security_headers(response):
    """Her response'a security headers ekle"""
    response.headers['Server'] = 'NabiSystem'
    response.headers['X-Powered-By'] = 'Python/Flask'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # HSTS header (SSL için)
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# ========== BEFORE REQUEST ==========
@app.before_request
def before_request():
    """Her request'ten önce güvenlik kontrolleri"""
    # Session timeout kontrolü
    if 'vip_logged_in' in session:
        login_time = session.get('login_time')
        if login_time:
            login_dt = datetime.fromisoformat(login_time)
            if datetime.now() - login_dt > timedelta(minutes=30):
                session.clear()
                return redirect(url_for('anasayfa'))
    
    # Basic path traversal koruması
    path = request.path
    if '..' in path or '//' in path:
        abort(403)

# ========== MAIN ==========
if __name__ == '__main__':
    # Production ayarları
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(32).hex()),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
        JSONIFY_PRETTYPRINT_REGULAR=False,
        JSON_SORT_KEYS=False,
        TRAP_HTTP_EXCEPTIONS=True,
        TRAP_BAD_REQUEST_ERRORS=True
    )
    
    # Render.com için port ayarı
    port = int(os.environ.get('PORT', 5000))
    
    # Production'da debug kapalı
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
          )
