from flask import Flask
from app.routes import main
from app.models import db
from config import Config
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta
from flask_mail import Mail
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config.from_object(Config)

CORS(app, supports_credentials=True)

app.config['MAIL_SERVER'] = 'mail.smtp2go.com'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'info-flowreserve.es'  # Tu usuario de SMTP2GO
app.config['MAIL_PASSWORD'] = 'zqKl6jwXYnzaM9mw'  # Tu contraseña de SMTP2GO
app.config['MAIL_DEFAULT_SENDER'] = 'agustin.dasilva@flowreserve.es'  # Remitente por defecto

mail = Mail(app)

# Inicializa la base de datos con la aplicación
db.init_app(app)

jwt = JWTManager(app)

# Configuración de la carpeta de subida
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'media')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SESSION_COOKIE_HTTPONLY'] = True   # Para evitar acceso desde JavaScript
app.config['SESSION_COOKIE_SECURE'] = True     # Para que la cookie solo se envíe por HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Protección contra CSRF

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

xlsx_template = os.path.join(os.getcwd(), 'app/xlsx_template/Informe_EXCEL.xlsx')
app.config['xlsx_template'] = xlsx_template

# Asegúrate de que la carpeta 'media' exista
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Registrar el blueprint
app.register_blueprint(main)

if __name__ == "__main__":
    app.run(debug=True)