from run import app
from app.models import db

with app.app_context():
    db.create_all()
