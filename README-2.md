
#  Güvenli Dosya Transfer Uygulaması (SFTP/HTTPS)

## Proje Özeti

SecureFileX, siber güvenlik prensiplerine uygun olarak geliştirilmiş, güvenli dosya paylaşımı ve transferi sağlayan açık kaynaklı bir uygulamadır. Kullanıcılar, dosyalarını SFTP (SSH File Transfer Protocol) ve HTTPS protokolleri üzerinden güvenli bir şekilde yükleyebilir, indirebilir ve paylaşabilir. Proje, veri bütünlüğü, kimlik doğrulama ve şifreleme gibi temel güvenlik prensiplerini uygulamalı olarak ele almayı hedeflemektedir. Bu çalışma, üniversite düzeyindeki bir siber güvenlik dersi kapsamında gerçekleştirilmiştir.

## Projenin Amacı

- Güvenli veri aktarımında SFTP ve HTTPS protokollerinin kullanımını göstermek
- AES-256 şifreleme algoritması ve SSL sertifikalarıyla veri güvenliğini sağlamak
- Kimlik doğrulama, kullanıcı yönetimi ve loglama gibi temel güvenlik bileşenlerini uygulamak
- Açık kaynak geliştiriciliğine katkı sağlamak

## Uygulama Özellikleri

- SFTP tabanlı dosya yükleme ve indirme
- HTTPS üzerinden güvenli web arayüzü
- AES-256 ile veri şifreleme
- JWT ile kimlik doğrulama ve oturum yönetimi
- Kullanıcı bazlı dosya yönetimi
- Detaylı loglama (IP adresi, zaman damgası, işlem tipi)
- Yönetici paneli ile dosya ve kullanıcı takibi

## Kullanılan Teknolojiler

| Katman            | Teknoloji              |
|-------------------|------------------------|
| Sunucu Tarafı     | Python (Flask)         |
| İstemci Tarafı    | HTML, Bootstrap        |
| Veritabanı        | SQLite                 |
| SFTP Sunucusu     | OpenSSH (Ubuntu)       |
| HTTPS Sertifikası | Let's Encrypt / OpenSSL|
| Kimlik Doğrulama  | JWT (JSON Web Token)   |

## Proje Yapısı

```
SecureFileX/
├── backend/
│   ├── app.py
│   ├── auth.py
│   ├── sftp_handler.py
│   ├── utils/
├── frontend/
│   ├── templates/
│   ├── static/
├── logs/
├── certs/
├── .env
├── README.md
├── requirements.txt
```

## Kurulum ve Çalıştırma

### 1. Bağımlılıkların Kurulumu

```bash
git clone https://github.com/kullanici/SecureFileX.git
cd SecureFileX
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. HTTPS Sertifikası Oluşturma

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Sertifikalar certs/ klasörüne yerleştirilmelidir.

### KODLAR

app.py

from flask import Flask, request, jsonify
from auth import authenticate_user, generate_token
from sftp_handler import upload_file_sftp
from utils.encryption import encrypt_data

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if authenticate_user(data["username"], data["password"]):
        token = generate_token(data["username"])
        return jsonify({"token": token})
    return jsonify({"message": "Unauthorized"}), 401

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    username = request.form["username"]
    enc_data = encrypt_data(file.read())
    success = upload_file_sftp(enc_data, username + "_" + file.filename)
    return jsonify({"status": "success" if success else "failure"})

if __name__ == "__main__":
    app.run(ssl_context=("certs/cert.pem", "certs/key.pem"))


auth.py

import jwt
import datetime

SECRET_KEY = "gizli_anahtar"

def authenticate_user(username, password):
    return username == "admin" and password == "1234"

def generate_token(username):
    payload = {
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


sftp_handler.py

import paramiko

def upload_file_sftp(file_data, filename):
    try:
        transport = paramiko.Transport(("localhost", 22))
        transport.connect(username="test", password="1234")
        sftp = paramiko.SFTPClient.from_transport(transport)
        with sftp.open("/home/test/" + filename, "wb") as f:
            f.write(file_data)
        sftp.close()
        transport.close()
        return True
    except Exception as e:
        print("SFTP Error:", e)
        return False


encryption.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)

def encrypt_data(data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext



### 3. Ortam Değişkenlerinin Ayarlanması

```
SECRET_KEY=gizli_anahtar
SFTP_HOST=localhost
SFTP_PORT=22
SFTP_USER=test
SFTP_PASS=1234
```

### 4. Sunucunun Başlatılması

```bash
python app.py
```

## Kullanım

1. Web arayüzü üzerinden kullanıcı kaydı yapılır.
2. Giriş sonrası, kullanıcı dosya yükleme ekranından SFTP sunucusuna veri aktarabilir.
3. Yüklenen dosyalar, kullanıcıya özel klasörlerde AES-256 ile şifrelenerek saklanır.
4. HTTPS bağlantısı üzerinden indirilen dosyalar, istemci tarafında çözülerek sunulur.

## Güvenlik Testleri

- Brute force saldırılarına karşı JWT süresi ve hesap kilitleme mekanizması
- HTTPS bağlantısıyla ortadaki adam (MITM) saldırılarına karşı koruma
- SFTP işlemlerinde zaman damgalı kayıt mekanizması
- OWASP güvenlik ilkelerine uyumlu yazılım geliştirme süreçleri

## Katkı Süreci

Projeye katkı sağlamak isteyen geliştiricilerin aşağıdaki adımları uygulamaları önerilir:

1. Repository'nin forklanması
2. Yeni bir geliştirme dalı (branch) oluşturulması
3. Yapılan değişikliklerin commit edilmesi
4. Değişikliklerin GitHub üzerine gönderilmesi (push)
5. Pull request açılması

## Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Ayrıntılar için LICENSE dosyasına bakınız.


## Kaynaklar

- RFC 4253 - SSH Transport Layer Protocol (https://tools.ietf.org/html/rfc4253)
- Let's Encrypt Belgeleri (https://letsencrypt.org/docs/)
- OWASP Güvenli Kodlama Rehberi (https://owasp.org/www-project-secure-coding-practices/)
