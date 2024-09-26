from flask import Blueprint, render_template, redirect, url_for, jsonify, request, session, current_app as app, send_from_directory
from app.models import db, bcrypt, User, File, Patient, Request, Invitation
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from werkzeug.utils import secure_filename
from flask_cors import cross_origin
from app.utils import generate_2fa_secret, generate_qr_code, get_totp_uri
import pyotp
import uuid
import qrcode
from io import BytesIO
import base64
import os
from datetime import datetime
import string
import random


main = Blueprint('main', __name__)

# to register a new user into the database
@main.route('/api/register', methods=['POST'])
@cross_origin()
def register_user():
    data = request.get_json()
    invitation_code = data.get('invitation_code')

    invitation = Invitation.query.filter_by(code=invitation_code, is_used=False).first()

    if not invitation:
        return jsonify({'error': 'Invalid or used invitation code'}), 400
    
    # Validar si ya existe un usuario con ese email
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message="El correo electrónico ya está en uso."), 400

    # Crear un nuevo usuario
    new_user = User(
        firstName=data['firstName'],
        lastName=data['lastName'],
        email=data['email'],
        password=bcrypt.generate_password_hash(data['password']).decode('utf-8')
    )

    # Guardar el nuevo usuario en la base de datos
    db.session.add(new_user)
    db.session.commit()

    # Generar el secreto 2FA para el usuario
    secret = pyotp.random_base32()
    new_user.two_factor_secret = secret
    db.session.commit()

    # Generar la URI de TOTP para el usuario
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(new_user.email, issuer_name="YourAppName")

    # Generar el código QR
    img = qrcode.make(totp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    # Generar un JWT para el usuario
    access_token = create_access_token(identity={'email': new_user.email})

    invitation.is_used = True
    db.session.commit()

    # Devolver el token y el código QR en base64 al frontend
    return jsonify(access_token=access_token, qr_code_base64=img_base64), 201

@main.route('/api/new_patient', methods=['POST'])
@cross_origin()
@jwt_required()  # Requiere autenticación
def add_patient():
    try:
        # Obtener el diccionario completo desde el token JWT
        current_user_data = get_jwt_identity()

        # Asegurarse de que obtienes el correo electrónico desde el diccionario
        current_user_email = current_user_data['email'] if isinstance(current_user_data, dict) else current_user_data

        # Obtener los datos enviados por el usuario
        data = request.get_json()

        # Validar que el campo 'nhc' esté presente en la solicitud
        if not data or 'nhc' not in data:
            return jsonify(message="NHC es requerido"), 400

        nhc = data['nhc']

        # Crear una nueva instancia de Patient con el email del usuario
        new_patient = Patient(nhc=nhc, user_email=current_user_email)

        # Añadir el nuevo paciente a la base de datos
        db.session.add(new_patient)
        db.session.commit()

        return jsonify(message="Paciente añadido exitosamente", patient_id=new_patient.id), 201

    except Exception as e:
        db.session.rollback()  # Revertir la transacción en caso de error
        return jsonify(message="Error añadiendo paciente", error=str(e)), 500

# to log in to the app
@main.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        if user.two_factor_enabled:
            # En lugar de usar la sesión, devolvemos un token temporal con el user_id
            temp_token = create_access_token(identity={'user_id': user.id}, expires_delta=False)
            return jsonify(message="2FA required", temp_token=temp_token), 202  # Código 202 para indicar que falta 2FA
        else:
            # Si no tiene 2FA habilitado, generamos el token JWT de acceso completo
            access_token = create_access_token(identity={'id': user.id, 'email': user.email})
            return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="Invalid credentials"), 401



# to test protected endpoints
@main.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    main.run(debug=True)

# lists all the users stored inside the database
@main.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()  # Consulta todos los usuarios en la base de datos
    users_list = []
    for user in users:
        users_list.append({
            'id': user.id,
            'username': user.firstName + " " + user.lastName,
            'email': user.email
        })
    return jsonify(users_list)  # Retorna la lista de usuarios en formato JSON

@main.route('/api/patients', methods=['GET'])
@cross_origin()
@jwt_required()
def get_patients_for_user():
    # Obtener el email del usuario autenticado desde el token JWT
    current_user_data = get_jwt_identity()
    current_user_email = current_user_data['email'] if isinstance(current_user_data, dict) else current_user_data

    # Filtrar los pacientes por el email del usuario autenticado
    patients = Patient.query.filter_by(user_email=current_user_email).all()

    # Crear una lista para enviar los pacientes en formato JSON
    patient_list = [{'id': p.id, 'nhc': p.nhc, 'user_email': p.user_email} for p in patients]

    return jsonify(patient_list), 200

@main.route('/api/patients/<nhc>', methods=['GET'])
@cross_origin()
@jwt_required()  # Requiere autenticación JWT
def get_patient_by_nhc(nhc):
    try:
        # Obtener el email del usuario logueado desde el token JWT
        current_user = get_jwt_identity()

        # Buscar al paciente con el NHC dado y que pertenezca al usuario actual (user_email)
        patient = Patient.query.filter_by(nhc=nhc, user_email=current_user['email']).first()

        # Si no se encuentra el paciente, devolver un error 404
        if not patient:
            return jsonify({"message": "Paciente no encontrado o no pertenece al usuario"}), 404

        # Devolver los datos del paciente en formato JSON
        return jsonify({
            'id': patient.id,
            'nhc': patient.nhc,
            'user_email': patient.user_email
        }), 200

    except Exception as e:
        return jsonify({"message": "Ocurrió un error", "error": str(e)}), 500


@main.route('/api/user', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_identity = get_jwt_identity()
    current_user = User.query.filter_by(email=current_user_identity['email']).first()

    if current_user:
        user_data = {
            'id': current_user.id,
            'full_name': current_user.firstName + " " + current_user.lastName,
            'email': current_user.email
        }
        return jsonify(user_data)
    else:
        return jsonify({'message': 'User not found'})

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx', 'vtp'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
        # Comprobar si se ha enviado un archivo
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    # Si no se selecciona ningún archivo
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Extraer el nombre y la extensión del archivo
        name, ext = os.path.splitext(filename)
        ext = ext.lstrip('.')

        # Obtener la identidad del usuario
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user['email']).first()

        # Guardar la información del archivo en la base de datos
        new_file = File(filename=name, extension=ext, filepath=file_path, user_id=user.id)
        db.session.add(new_file)
        db.session.commit()

        return jsonify({"message": "File uploaded successfully", "file_path": file_path}), 201
    else:
        return jsonify({"error": "File type not allowed"}), 400
    
@main.route('/api/files', methods=['GET'])
@jwt_required()
def get_files():
    files = File.query.all()  # files es una lista de objetos File
    files_list = [
        {
            "id": file.id,
            "filename": file.filename,
            "extension": file.extension,
            "filepath": file.filepath,
            "upload_date": file.upload_date,
            "user_id": file.user_id,
            "username": file.user.firstName + " " + file.user.lastName,
        }
        for file in files  # Aquí iteramos correctamente sobre cada objeto File en la lista files
    ]
    return jsonify(files_list), 200

@main.route('/api/files/<filename>')
def get_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@main.route('/enable-2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()

    if user and not user.two_factor_enabled:
        # Generar el secreto 2FA
        secret = pyotp.random_base32()
        user.two_factor_secret = secret
        user.two_factor_enabled = True
        db.session.commit()

        # Generar la URI de TOTP
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(user.email, issuer_name="YourAppName")

        # Crear el código QR
        img = qrcode.make(totp_uri)

        # Convertir la imagen a base64
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        # Devolver la imagen base64 en el JSON
        return jsonify(qr_code_base64=img_base64), 200
    else:
        return jsonify(message="2FA already enabled"), 400

@main.route('/api/verify-2fa', methods=['POST'])
@cross_origin()
def verify_2fa():
    # Obtener el temp_token del encabezado de la solicitud o el cuerpo
    temp_token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not temp_token:
        return jsonify(message="Missing temporary token"), 400

    try:
        # Decodificamos el token temporal para obtener el user_id
        decoded_token = decode_token(temp_token)
        user_id = decoded_token['sub']['user_id']
    except Exception as e:
        return jsonify(message="Invalid or expired temporary token", error=str(e)), 400
    
    # Ahora buscamos al usuario en la base de datos usando el user_id
    user = User.query.filter_by(id=user_id).first()

    if not user or not user.two_factor_enabled:
        return jsonify(message="2FA is not enabled for this user"), 400

    # Obtener el código ingresado por el usuario
    code = request.json.get('twofa_code')

    # Verificar el código TOTP
    totp = pyotp.TOTP(user.two_factor_secret)
    if totp.verify(code):
        # Si el código es válido, generamos el JWT completo
        access_token = create_access_token(identity={'id': user.id, 'email': user.email})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify(message="Invalid 2FA code"), 400

@main.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify(message=f"Welcome {current_user['email']}"), 200

@main.route('/api/requests', methods=['POST'])
@jwt_required()
@cross_origin()
def create_request():
    current_user = get_jwt_identity()  # Obtener el usuario logueado
    print(current_user)
    nhc_patient = request.form.get('nhc_patient')  # Obtener el NHC del paciente
    pressure = request.form.get('pressure')
    state = request.form.get('state', 0)  # Obtener el estado de la solicitud

    # Buscar al paciente por NHC
    patient = Patient.query.filter_by(nhc=nhc_patient).first()
    if not patient:
        return jsonify(message="Paciente no encontrado"), 404

    # Crear la solicitud (Request)
    new_request = Request(
        user_email=current_user['email'],
        nhc_patient=nhc_patient,
        state=state,
        date=datetime.utcnow(),
        pressure=pressure
    )
    db.session.add(new_request)
    db.session.commit()

    # Guardar los archivos
    if 'files' in request.files:
        files = request.files.getlist('files')  # Obtener todos los archivos
        for file in files:
            # Obtener el nombre original y la extensión del archivo
            original_filename = secure_filename(file.filename)
            name, extension = os.path.splitext(original_filename)  # Separar nombre y extensión

            # Generar un nombre único para el archivo usando UUID
            unique_filename = f"{name}_{uuid.uuid4().hex}{extension}"  # Formato: nombre_original_UUID.ext
            
            # Guardar el archivo en el sistema de archivos
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)

            # Crear el objeto File y asociarlo a la solicitud
            new_file = File(
                filename=unique_filename,
                extension=extension.replace(".", ""),  # Remover el punto de la extensión
                filepath=filepath,
                user_id=current_user['id'],
                request_id=new_request.id
            )
            db.session.add(new_file)

    db.session.commit()

    return jsonify(message="Solicitud creada exitosamente", request_id=new_request.id), 201


@main.route('/api/get_request', methods=['GET'])
@cross_origin()
@jwt_required()
def get_requests_for_user():
    # Definir el mapeo de los estados
    state_mapping = {
        0: "Solicitud realizada",
        1: "Aceptada",
        2: "Rechazada",
        3: "En progreso",
        4: "Completada"
    }

    current_user_data = get_jwt_identity()
    current_user_email = current_user_data['email'] if isinstance(current_user_data, dict) else current_user_data

    requests = Request.query.filter_by(user_email=current_user_email).all()

    request_list = [
        {
            'id': r.id,
            'nhc_patient': r.nhc_patient,
            'date': r.date,
            'state': state_mapping.get(r.state, "Estado Desconocido")  # Mapeo del estado a su string
        }
        for r in requests
    ]

    return jsonify(request_list), 200

def generate_invitation_code(length=8):
    characters = string.ascii_uppercase + string.digits
    code = ''.join(random.choice(characters) for _ in range(length))
    return code

# Ruta para generar y devolver el código de invitación
@main.route('/api/generate-invitation', methods=['POST'])
def generate_invitation():
    invitation_code = generate_invitation_code()  # Generar el código

    # Guardar el código en la base de datos
    new_invitation = Invitation(code=invitation_code, is_used=False)  # 'used' para saber si se ha utilizado
    db.session.add(new_invitation)
    db.session.commit()

    return jsonify({'invitation_code': invitation_code}), 201