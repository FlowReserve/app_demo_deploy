from flask import Flask
from app.routes import main
from app.models import db, bcrypt
from config import Config
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)

    jwt = JWTManager(app)

    bcrypt.init_app(app)
    
    app.register_blueprint(main)
    
    return app
