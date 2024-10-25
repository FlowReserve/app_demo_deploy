from flask import Flask
from app.routes import main
from app.models import db
from config import Config
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config.from_object(Config)

CORS(app, supports_credentials=True)

# Inicializa la base de datos con la aplicación
db.init_app(app)


jwt = JWTManager(app)

# Configuración de la carpeta de subida
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'media')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SESSION_COOKIE_HTTPONLY'] = True   # Para evitar acceso desde JavaScript
app.config['SESSION_COOKIE_SECURE'] = True     # Para que la cookie solo se envíe por HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protección contra CSRF

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

xlsx_template = os.path.join(os.getcwd(), 'app/xlsx_template/Informe_EXCEL.xlsx')
app.config['xlsx_template'] = xlsx_template

# Asegúrate de que la carpeta 'media' exista
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Registrar el blueprint
app.register_blueprint(main)

if __name__ == '__main__':
    with app.app_context():  # Esto asegura que el contexto de la aplicación esté activo
        db.create_all()  # Crear las tablas en la base de datos si no existen
    app.run(debug=True)
