import pyotp
import qrcode
from io import BytesIO
from flask import send_file

def generate_2fa_secret():
    return pyotp.random_base32()

def get_totp_uri(username, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(
        username, issuer_name="YourAppName"  # Cambia "YourAppName" por el nombre de tu app
    )

def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
