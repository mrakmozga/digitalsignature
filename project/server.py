from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import base64
import random

app = Flask(__name__)

# Разрешаем CORS для всех маршрутов чтобы браузер мог
# обращаться к серверу с другого порта (8080 → 5000)
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# Браузер перед основным запросом делает preflight-запрос методом OPTIONS —
# отвечаем пустым 200 чтобы он пропустил основной запрос
@app.route('/verify', methods=['OPTIONS'])
@app.route('/public-key', methods=['OPTIONS'])
@app.route('/sign-message', methods=['OPTIONS'])
def options_handler():
    return jsonify({}), 200

# Ключевая пара сервера генерируется один раз при запуске.
# e=65537 — стандартная публичная экспонента, key_size=2048 — длина модуля в битах
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

# Набор сообщений для случайной выборки в сценарии 2
MESSAGES = [
    "Транзакция #4821 подтверждена. Сумма: 15,000 руб.",
    "Сертификат выдан пользователю Иванов И.И. 12.03.2026",
    "Документ подписан и отправлен в архив.",
    "Авторизация успешна. Сессия открыта в 14:32 UTC.",
    "Контракт №77-Б принят к исполнению."
]

def get_server_public_key_pem():
    # Сериализуем публичный ключ в формат PEM (текстовый Base64 с заголовками)
    # SubjectPublicKeyInfo — стандартный формат X.509 для публичных ключей
    return server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# --- Сценарий 1: верификация подписи клиента ---

@app.route('/verify', methods=['POST'])
def verify_client_signature():
    data = request.json

    # Декодируем входные данные: сообщение в байты, подпись из Base64, ключ из PEM
    message = data['message'].encode()
    signature = base64.b64decode(data['signature'])
    public_key_pem = data['public_key'].encode()

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)

        # verify() вычисляет SHA-256 от message и сравнивает с хэшем внутри подписи.
        # Если не совпадает — бросает InvalidSignature
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())

        return jsonify({
            "verified": True,
            "message": "Подпись верна! Сообщение подлинное и не изменялось.",
            "algorithm": "RSA-2048 + SHA-256"
        })
    except InvalidSignature:
        return jsonify({
            "verified": False,
            "message": "Подпись недействительна! Сообщение могло быть изменено.",
            "algorithm": "RSA-2048 + SHA-256"
        })
    except Exception as e:
        return jsonify({"verified": False, "message": f"Ошибка: {str(e)}", "algorithm": "—"})


# --- Сценарий 2: сервер выступает источником подписанного сообщения ---

@app.route('/public-key', methods=['GET'])
def get_public_key():
    # Клиент запрашивает публичный ключ заранее, чтобы затем верифицировать подпись локально
    return jsonify({"public_key": get_server_public_key_pem()})

@app.route('/sign-message', methods=['GET'])
def sign_message():
    message = random.choice(MESSAGES)

    # Подписываем байты сообщения приватным ключом сервера.
    # PKCS1v15 — схема дополнения, SHA256 — алгоритм хэширования перед подписью.
    # Результат — бинарные данные, кодируем в Base64 для передачи через JSON
    signature = server_private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())

    return jsonify({
        "message": message,
        "signature": base64.b64encode(signature).decode(),
        "algorithm": "RSA-2048 + SHA-256"
    })


if __name__ == '__main__':
    print("Сервер ЭЦП запущен на http://localhost:5000")
    app.run(host='0.0.0.0', debug=False, port=5000)
