from flask import Flask
from app.routes import main
from app.models import db
from config import Config
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import os

app = Flask(__name__)
app.config.from_object(Config)

CORS(app)

# Inicializa la base de datos con la aplicación
db.init_app(app)

jwt = JWTManager(app)

# Configuración de la carpeta de subida
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'media')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Asegúrate de que la carpeta 'media' exista
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Registrar el blueprint
app.register_blueprint(main)

if __name__ == "__main__":
    app.run(debug=True)
