from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import time
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'nabi_system_secure_key_2024_v2')

# ========== RENDER UYUMLU RATE LIMITER ==========

def get_render_ip():
    """Render.com'da doğru client IP'yi al"""
    # Önce X-Forwarded-For header'ını kontrol et
    if request.headers.get('X-Forwarded-For'):
        # İlk IP'yi al (client IP)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    # X-Real-IP header'ını kontrol et
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    
    # Varsayılan Flask IP algılama
    return get_remote_address()

# Flask-Limiter konfigürasyonu
limiter = Limiter(
    get_render_ip,
    app=app,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://",
    strategy="moving-window",
    headers_enabled=True
)

# Basit rate limiting
class SimpleRateLimiter:
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, ip, path, limit=150, window=60):
        current_time = time.time()
        
        # Render internal IP'lerini ve özel path'leri atla
        if ip in ['127.0.0.1', 'localhost', '::1', '172.17.0.1']:
            return True
            
        if path in ['/health', '/favicon.ico', '/robots.txt']:
            return True
            
        key = f"{ip}:{path}"
        
        if key not in self.requests:
            self.requests[key] = []
        
        window_start = current_time - window
        self.requests[key] = [req_time for req_time in self.requests[key] if req_time > window_start]
        
        if len(self.requests[key]) >= limit:
            return False
            
        self.requests[key].append(current_time)
        return True

simple_limiter = SimpleRateLimiter()

@app.before_request
def check_rate_limit():
    """Rate limit kontrolü"""
    ip = get_render_ip()
    path = request.path
    
    if not simple_limiter.is_allowed(ip, path, limit=200, window=60):
        abort(429, description="Rate limit exceeded. Please wait a minute.")

# ========== VIP KULLANICI SISTEMI ==========

VIP_USERS = {
    "admin": {"password": "babapro", "key": "MERHAMETLI-VIP-2024"},
    "vip": {"password": "skskkdkdjf", "key": "NABI-VIP-2024"},
    "user": {"password": "kaoqowiwisis", "key": "NABI-VIP-2024"}
}

# ========== API LISTELERI ==========

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

# ========== ROUTES ==========

@app.route('/')
@limiter.limit("200 per hour")
def anasayfa():
    return render_template(
        'anasayfa.html', 
        free_apis=FREE_APIS, 
        vip_apis=VIP_APIS,
        vip_count=len(VIP_APIS),
        free_count=len(FREE_APIS)
    )

@app.route('/vip_giris', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def vip_giris():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        vip_key = request.form.get('vip_key', '').strip()
        
        if username in VIP_USERS:
            user = VIP_USERS[username]
            if password == user['password'] and vip_key == user['key']:
                session['vip_logged_in'] = True
                session['vip_username'] = username
                session['login_time'] = datetime.now().isoformat()
                return redirect(url_for('vip_api'))
        
        return render_template('vipgiris.html', error="Geçersiz kullanıcı adı, şifre veya VIP anahtarı!")
    
    return render_template('vipgiris.html')

@app.route('/vip_api')
@limiter.limit("300 per hour")
def vip_api():
    if 'vip_logged_in' not in session:
        return redirect(url_for('vip_giris'))
    
    # Session timeout kontrolü (60 dakika)
    if 'login_time' in session:
        login_time = datetime.fromisoformat(session['login_time'])
        if (datetime.now() - login_time).seconds > 3600:
            session.clear()
            return redirect(url_for('vip_giris'))
    
    # API'leri kategorilere ayır
    categories = {
        "Temel Bilgiler": [],
        "Aile Bilgileri": [],
        "İş ve Finans": [],
        "Diğer": []
    }
    
    for api in VIP_APIS:
        desc_lower = api['desc'].lower()
        
        if any(word in desc_lower for word in ['cinsiyet', 'yaş', 'din', 'burç', 'medeni', 'doğum']):
            categories["Temel Bilgiler"].append(api)
        elif any(word in desc_lower for word in ['aile', 'baba', 'anne', 'kardeş', 'çocuk', 'amca', 'dayı', 'hala', 'teyze', 'kuzen', 'dede', 'nine', 'sülale']):
            categories["Aile Bilgileri"].append(api)
        elif any(word in desc_lower for word in ['iş', 'işyeri', 'verg', 'iban', 'finans', 'plaka']):
            categories["İş ve Finans"].append(api)
        else:
            categories["Diğer"].append(api)
    
    return render_template(
        'vipapi.html', 
        categories=categories,
        username=session.get('vip_username', 'Kullanıcı'),
        login_time=session.get('login_time'),
        total_apis=len(VIP_APIS)
    )

@app.route('/satin_al')
@limiter.limit("100 per hour")
def satin_al():
    return render_template('satinal.html')

@app.route('/cikis')
def cikis():
    session.clear()
    return redirect(url_for('anasayfa'))

@app.route('/api_test/<api_name>')
@limiter.limit("50 per minute")
def api_test(api_name):
    if 'vip_logged_in' not in session:
        return redirect(url_for('vip_giris'))
    
    api = next((a for a in VIP_APIS if a['name'] == api_name), None)
    if not api:
        return "API bulunamadı", 404
    
    return f"""
    <h3>API Test: {api['name']}</h3>
    <p><strong>Açıklama:</strong> {api['desc']}</p>
    <p><strong>Endpoint:</strong> {api['endpoint']}</p>
    <p><strong>Örnek Kullanım:</strong> {api['endpoint']}12345678901</p>
    <a href="/vip_api">Geri Dön</a>
    """

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/health')
def health_check():
    return {
        "status": "healthy",
        "service": "Nabi System API",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }

@app.route('/robots.txt')
def robots():
    return """User-agent: *
Disallow: /vip_giris
Disallow: /vip_api
Disallow: /satin_al
Allow: /
"""

# ========== ERROR HANDLERS ==========

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="Sayfa bulunamadı!"), 404

@app.errorhandler(429)
def too_many_requests(error):
    return render_template('error.html', error_code=429, error_message="Çok fazla istek! Lütfen bir dakika bekleyin."), 429

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error_code=500, error_message="Sunucu hatası! Lütfen daha sonra tekrar deneyin."), 500

# ========== AFTER REQUEST ==========

@app.after_request
def add_security_headers(response):
    """Security headers ekle"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ========== MAIN ==========

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
      )
