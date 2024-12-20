from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from nanoid import generate

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(150), unique=False, nullable=False)
    lastName = db.Column(db.String(150), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.Integer, nullable=False, default=0)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    two_factor_enabled = db.Column(db.Boolean, default=True)
    two_factor_secret = db.Column(db.String(64))

    def __repr__(self):
        return f'<User {self.username}>'
    
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nhc = db.Column(db.String(120), unique=True, nullable=False)
    user_email = db.Column(db.String(120), db.ForeignKey('user.email'), nullable=False)

    # Relación de uno a muchos con Request
    requests = db.relationship('Request', backref='patient', lazy=True)

    nanoid = db.Column(db.String(8), unique=True, nullable=False, default=lambda: f"PAT-{generate('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 8)}")

    # Relación con User (un usuario puede tener varios pacientes)
    user = db.relationship('User', backref=db.backref('patients', lazy=True))

    def __repr__(self):
        return f"<Patient {self.nhc} >"
        
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), db.ForeignKey('user.email'), nullable=False)  # Referencia al usuario
    nhc_patient = db.Column(db.String(120), db.ForeignKey('patient.nhc'), nullable=False)  # Referencia al NHC del paciente
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Fecha de la solicitud
    state = db.Column(db.Integer, nullable=False, default=0)  # Estado de la solicitud (valores de 0 a 4)
    pressure = db.Column(db.String(10), nullable=False)
    nanoid = db.Column(db.String(8), unique=True, nullable=False, default=lambda: f"FR-{generate('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 8)}")

    # Relación con los archivos (Request puede tener múltiples archivos)
    files = db.relationship('File', backref='request', lazy=True)

    def __repr__(self):
        return f"<Request {self.id}, State: {self.state}>"

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    extension = db.Column(db.String(10), nullable=False)
    filepath = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)  # Relación con la solicitud
    user = db.relationship('User', backref=db.backref('files', lazy=True))

    def __repr__(self):
        return f"File('{self.filename}', '{self.extension}', '{self.filepath}', '{self.upload_date}')"

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    filepath = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Referencia a la solicitud (Request)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    request = db.relationship('Request', backref=db.backref('reports', lazy=True))

    def __repr__(self):
        return f"<Report {self.filename} uploaded at {self.upload_date}>"


class Invitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(120), unique=True, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)