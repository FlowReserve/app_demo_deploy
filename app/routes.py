from flask import Blueprint, render_template, redirect, url_for, jsonify, send_file, request, session, current_app as app, send_from_directory
from itsdangerous import URLSafeTimedSerializer
from app.models import db, bcrypt, User, File, Patient, Request, Invitation, Report
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
from datetime import datetime, timedelta
import string
import random
import zipfile
from io import BytesIO
from flask_mail import Mail, Message
import urllib.parse
import re

main = Blueprint('main', __name__)

def get_serializer():
    return URLSafeTimedSerializer(app.secret_key)

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

    def is_valid_password(password):
        # Al menos 8 caracteres, una letra, un número y un carácter especial
        regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]{8,}$'
        return re.match(regex, password) is not None

    if not is_valid_password(data['password']):
        return jsonify({'error': 'La contraseña debe tener al menos 8 caracteres, una letra, un número y un carácter especial.'}), 400

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

@main.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    print("Request data:", data)  # Agrega este print para ver los datos
    user = User.query.filter_by(email=data.get('email')).first()

    if not user:
        return jsonify({'error': 'El correo no está registrado.'}), 404

    reset_token = create_access_token(identity={'email': user.email}, expires_delta=timedelta(hours=1))
    parsed_token = urllib.parse.quote(reset_token)

    msg = Message(subject="Restablecimiento de contraseña",
                  sender="agustin.dasilva@flowreserve.es",
                  recipients=[user.email])
    msg.body = f"Utiliza el siguiente enlace para restablecer tu contraseña: https://flowreserve.github.io/app_demo_deploy_front/#/static/password-reset?token={parsed_token}"

    print("Sending email to:", user.email)  # Agrega este print para confirmar que el correo se está enviando

    try:
        app.extensions['mail'].send(msg)
        print("Email sent successfully")  # Este mensaje debería aparecer si el correo se envió correctamente
        return jsonify({'message': 'Se ha enviado un enlace de recuperación a tu correo electrónico.'}), 200
    except Exception as e:
        print("Error sending email:", e)  # Esto mostrará cualquier error con el correo
        return jsonify({'error': 'Error al enviar el correo. Inténtelo de nuevo más tarde.'}), 500

@main.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({'error': 'Token y contraseña son obligatorios'}), 400

    try:
        # Decodificar el token
        decoded_token = decode_token(token)

        # Extraer el email del token
        email = decoded_token['sub']['email']

        # Verificar si el usuario existe
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        def is_valid_password(password):
        # Al menos 8 caracteres, una letra, un número y un carácter especial
            regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]{8,}$'
            return re.match(regex, password) is not None

        if not is_valid_password(data['password']):
            return jsonify({'error': 'La contraseña debe tener al menos 8 caracteres, una letra, un número y un carácter especial.'}), 400

        # Actualizar la contraseña
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

        return jsonify({'message': 'Contraseña restablecida correctamente'}), 200

    except Exception as e:
        print(f"Error al decodificar el token: {str(e)}")  # Log del error
        return jsonify({'error': 'El enlace es inválido o ha expirado'}), 400


@main.route('/api/hash-password', methods=['POST'])
def hash_password():
    data = request.get_json()
    password = data.get('password')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    # Generar el hash de la contraseña
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Devolver la contraseña hasheada
    return jsonify({'hashed_password': hashed_password}), 200


@main.route('/api/new_patient', methods=['POST'])
def add_patient():
    # Verificar si el usuario tiene una sesión activa
    if 'user_id' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    data = request.get_json()
    nhc = data.get('nhc')

    if not nhc:
        return jsonify({'message': 'NHC es requerido.'}), 400

    # Añadir el paciente a la base de datos
    new_patient = Patient(nhc=nhc, user_email=session['user_email'])
    db.session.add(new_patient)
    db.session.commit()

    return jsonify({'message': 'Paciente añadido exitosamente.', 'patient_id': new_patient.id}), 201


# to log in to the app
@main.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        if user.two_factor_enabled:
            # Marcar en la sesión que se requiere 2FA, pero aún no autenticar completamente al usuario
            session['user_id'] = user.id
            session['2fa_required'] = True  # Señalar que aún no se ha completado 2FA
            return jsonify(message="2FA required"), 202  # Código 202 para indicar que falta 2FA
        else:
            # No se requiere 2FA, autenticamos normalmente
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_role'] = user.role
            session.permanent = True  # Mantener la sesión activa durante el tiempo definido
            app.permanent_session_lifetime = timedelta(days=7)  # Duración de la sesión (en este caso, 7 días)
            print(session)
            return jsonify(message="successful", role=user.role), 200
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
    # Verificar si el usuario tiene una sesión activa
    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Verificar si el usuario tiene privilegios de administrador (opcional)
    if session.get('user_role') != 1:
        return jsonify({'message': 'No tienes permisos para acceder a esta información.'}), 403

    # Obtener la lista de todos los usuarios
    users = User.query.all()  # Consulta todos los usuarios en la base de datos
    users_list = []
    for user in users:
        users_list.append({
            'id': user.id,
            'username': user.firstName + " " + user.lastName,
            'firstName': user.firstName,
            'lastName': user.lastName,
            'email': user.email
        })
    
    # Retornar la lista de usuarios en formato JSON
    return jsonify(users_list), 200


@main.route('/api/all-requests', methods=['GET'])
def get_all_requests():
    # Verificar si el usuario tiene una sesión activa
    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Obtener todas las solicitudes de la base de datos
    requests = Request.query.all()

    # Crear una lista con la información de las solicitudes
    request_list = [
        {
            'id': r.id,
            'nanoid': r.nanoid,
            'date': r.date.strftime('%d/%m/%y'),
            'state': r.state,  # Mapeo del estado a su string
            'pressure': r.pressure
        }
        for r in requests
    ]

    # Devolver la lista de solicitudes en formato JSON
    return jsonify(request_list), 200


@main.route('/api/logout', methods=['POST'])
def logout():
    # Limpia la sesión actual del usuario
    session.clear()  # Elimina todos los datos de la sesión

    # Devuelve una respuesta al cliente indicando que el logout fue exitoso
    response = jsonify(message="Logout successful")
    
    # Configura la cookie de sesión para que expire
    response.set_cookie('session', '', expires=0)

    return response, 200

@main.route('/api/update-request/<int:request_id>', methods=['PUT'])
def update_request(request_id):
    try:
        # Verificar si el usuario está autenticado
        if 'user_email' not in session:
            return jsonify({'message': 'No estás autenticado.'}), 401

        # Verificar si el usuario tiene privilegios de administrador
        if session.get('user_role') != 1:
            return jsonify({'message': 'No tienes permisos para acceder a esta información.'}), 403

        # Obtener los datos enviados desde el frontend
        data = request.get_json()

        if not data:
            return jsonify({"error": "No se recibieron datos"}), 400

        print("Datos recibidos del frontend:", data)

        # Obtener el nuevo estado y el nanoid
        new_state = data.get('state')
        nanoid = data.get('nanoid')

        # Validar campos obligatorios
        if new_state is None or nanoid is None:
            return jsonify({"error": "Faltan campos obligatorios: state y nanoid son requeridos"}), 400

        try:
            # Asegurarse de que new_state sea un número entero
            new_state = int(new_state)
        except ValueError:
            return jsonify({"error": "El estado debe ser un número válido"}), 400

        # Buscar la solicitud por ID
        request_to_update = Request.query.get(request_id)

        if not request_to_update:
            return jsonify({"error": "Solicitud no encontrada"}), 404

        # Actualizar los datos de la solicitud
        request_to_update.state = new_state
        request_to_update.nanoid = nanoid

        # Guardar cambios en la base de datos
        db.session.commit()

        return jsonify({
            "message": "Solicitud actualizada con éxito",
            "request": {
                "id": request_to_update.id,
                "state": request_to_update.state,
                "nanoid": request_to_update.nanoid,
                "date": request_to_update.date.isoformat()
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        print("Error en el servidor:", str(e))
        return jsonify({"error": str(e)}), 500


@main.route('/api/request/<int:request_id>/edit', methods=['PUT'])
@jwt_required()
def edit_request(request_id):
    try:
        data = request.get_json()
        nhc_patient = data.get('nhc_patient')
        date_str = data.get('date')

        if nhc_patient is None or date_str is None:
            return jsonify({"error": "Campos obligatorios faltantes"}), 400

        # Convertir la fecha a objeto datetime
        date_obj = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %Z')

        request_to_update = Request.query.get(request_id)

        if not request_to_update:
            return jsonify({"error": "Solicitud no encontrada"}), 404

        # Actualizar los datos del formulario
        request_to_update.nhc_patient = nhc_patient
        request_to_update.date = date_obj

        db.session.commit()

        return jsonify({"message": "Solicitud actualizada con éxito", "request": {
            "nhc_patient": request_to_update.nhc_patient,
            "date": request_to_update.date.isoformat()
        }}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@main.route('/api/request/<int:request_id>/update-state', methods=['PUT'])
def update_request_state(request_id):
    try:

        if 'user_email' not in session:
            return jsonify({'message': 'No estás autenticado.'}), 401

    # Verificar si el usuario tiene privilegios de administrador (opcional)
        if session.get('user_role') != 1:
            return jsonify({'message': 'No tienes permisos para acceder a esta información.'}), 403

        data = request.get_json()
        new_state = data.get('state')

        if new_state is None:
            return jsonify({"error": "El campo 'state' es requerido"}), 400

        request_to_update = Request.query.get(request_id)

        if not request_to_update:
            return jsonify({"error": "Solicitud no encontrada"}), 404

        # Actualizar el estado de la solicitud
        request_to_update.state = int(new_state)
        db.session.commit()

        # Devolver la solicitud actualizada
        return jsonify({
            "message": "Estado actualizado con éxito",
            "request": {
                "id": request_to_update.id,
                "state": request_to_update.state,
                "nhc_patient": request_to_update.nhc_patient,
                "date": request_to_update.date.isoformat()
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@main.route('/api/upload_report', methods=['POST'])
def upload_report():

    if 'user_email' not in session:
            return jsonify({'message': 'No estás autenticado.'}), 401

    # Verificar si el usuario tiene privilegios de administrador (opcional)
    if session.get('user_role') != 1:
            return jsonify({'message': 'No tienes permisos para acceder a esta información.'}), 403
    

    # Verificar si el archivo PDF está presente en la solicitud
    if 'pdf' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['pdf']
    request_id = request.form.get('request_id')

    # Verificar si se proporcionó un archivo y un request_id válido
    if not request_id:
        return jsonify({"error": "No request ID provided"}), 400

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Verificar si el archivo tiene la extensión permitida
    if file and allowed_file(file.filename):
        try:
            # Verificar que la solicitud exista en la base de datos
            request_obj = Request.query.get(request_id)
            if not request_obj:
                return jsonify({"error": "Request not found"}), 404

            # Verificar si el estado de la solicitud ya es "Disponible para descargar"
            if request_obj.state == 'Disponible para descargar':
                return jsonify({"error": "PDF already uploaded and available for download"}), 400

            # Guardar el archivo PDF en el servidor
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Crear una nueva entrada en la tabla Reports
            report = Report(
                filename=filename,
                filepath=filepath,
                request_id=request_id
            )
            db.session.add(report)

            # Cambiar el estado de la solicitud a "Disponible para descargar"
            request_obj.state = 4

            # Guardar los cambios en la base de datos
            db.session.commit()

            return jsonify({"message": "File uploaded successfully", "state": "Disponible para descargar"}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "File type not allowed"}), 400

# Función auxiliar para validar que el archivo sea PDF
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

@main.route('/api/patients', methods=['GET'])
def get_patients_for_user():
    # Verificar si el usuario tiene una sesión activa
    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Obtener el email del usuario autenticado desde la sesión
    current_user_email = session['user_email']

    # Filtrar los pacientes por el email del usuario autenticado
    patients = Patient.query.filter_by(user_email=current_user_email).all()

    # Crear una lista para enviar los pacientes en formato JSON
    patient_list = [{'id': p.id, 'nhc': p.nhc, 'nanoid': p.nanoid, 'user_email': p.user_email} for p in patients]

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
def get_current_user():
    # Verificar si el usuario está autenticado revisando la sesión
    print(session)

    if 'user_email' not in session:
        return jsonify({'message': 'User not authenticated'}), 401

    # Obtener el email del usuario desde la sesión
    user_email = session.get('user_email')

    # Buscar el usuario en la base de datos por su email
    current_user = User.query.filter_by(email=user_email).first()

    if current_user:
        # Devolver la información del usuario en formato JSON
        user_data = {
            'id': current_user.id,
            'full_name': current_user.firstName + " " + current_user.lastName,
            'email': current_user.email,
            'role': current_user.role
        }
        return jsonify(user_data), 200
    else:
        return jsonify({'message': 'User not found'}), 404

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

@main.route('/api/request/<int:request_id>/download-report', methods=['GET'])
def download_report(request_id):
    # Buscar la solicitud en la base de datos

    
    request_obj = Request.query.get(request_id)
    
    if not request_obj:
        return jsonify({"error": "Request not found"}), 404

    # Buscar el reporte asociado a la solicitud
    report = Report.query.filter_by(request_id=request_id).first()
    
    if not report:
        return jsonify({"error": "Report not found"}), 404

    # Verificar que el archivo PDF existe en el sistema de archivos
    filepath = report.filepath
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found on server"}), 404

    try:
        # Usar send_file para enviar el archivo PDF al cliente
        return send_file(filepath, as_attachment=True, download_name=report.filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
def verify_2fa():
    # Verificar que 2FA es requerido y que el usuario está autenticado parcialmente
    if '2fa_required' not in session or 'user_id' not in session:
        return jsonify(message="2FA not required or session invalid"), 400

    user_id = session['user_id']
    user = User.query.filter_by(id=user_id).first()

    if not user or not user.two_factor_enabled:
        return jsonify(message="2FA is not enabled for this user"), 400

    # Obtener el código ingresado por el usuario
    code = request.json.get('twofa_code')

    # Verificar el código TOTP
    totp = pyotp.TOTP(user.two_factor_secret)

    if totp.verify(code):
        # Si el código es válido, completar la autenticación
        session['user_email'] = user.email
        session['user_role'] = user.role
        session.pop('2fa_required')  # Eliminar el estado de 2FA requerido
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)  # Mantener la sesión durante 7 días

        return jsonify(message="2FA verified, login successful"), 200
    else:
        return jsonify(message="Invalid 2FA code"), 400


@main.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify(message=f"Welcome {current_user['email']}"), 200

@main.route('/api/requests', methods=['POST'])
def create_request():
    # Verificar si el usuario tiene una sesión activa
    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Obtener el email del usuario autenticado desde la sesión
    current_user_email = session['user_email']
    
    nhc_patient = request.form.get('nhc_patient')  # Obtener el NHC del paciente
    pressure = request.form.get('pressure')
    state = request.form.get('state', 0)  # Obtener el estado de la solicitud

    # Buscar al paciente por NHC
    patient = Patient.query.filter_by(nhc=nhc_patient).first()
    if not patient:
        return jsonify(message="Paciente no encontrado"), 404

    # Crear la solicitud (Request)
    new_request = Request(
        user_email=current_user_email,
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
                user_id=session['user_id'],  # Obtener el user_id desde la sesión
                request_id=new_request.id
            )
            db.session.add(new_file)

    db.session.commit()

    return jsonify(message="Solicitud creada exitosamente", request_id=new_request.id), 201



@main.route('/api/get_request', methods=['GET'])
def get_requests_for_user():
    # Verificar si el usuario tiene una sesión activa
    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Definir el mapeo de los estados
    state_mapping = {
        0: "Solicitud realizada",
        1: "Aceptada",
        2: "Rechazada",
        3: "En progreso",
        4: "Completada"
    }

    # Obtener el email del usuario autenticado desde la sesión
    current_user_email = session['user_email']

    # Filtrar las solicitudes por el email del usuario autenticado
    requests = Request.query.filter_by(user_email=current_user_email).order_by(Request.date.desc()).all()

    # Crear una lista para enviar las solicitudes en formato JSON
    request_list = [
        {
            'id': r.id,
            'nhc_patient': r.nhc_patient,
            'nanoid': r.nanoid,
            'date': r.date,
            'state': state_mapping.get(r.state, "Estado Desconocido")  # Mapeo del estado a su string
        }
        for r in requests
    ]

    return jsonify(request_list), 200

@main.route('/api/get_request_by_patient', methods=['POST'])
def get_requests_by_patient():
    if 'user_email' not in session:  # Verificar sesión activa
        return jsonify({'message': 'No estás autenticado.'}), 401

    data = request.get_json()  # Obtener datos del cuerpo
    nhc_patient = data.get('nhc')  # Extraer el nhc

    if not nhc_patient:
        return jsonify({'message': 'NHC no proporcionado.'}), 400

    # Definir mapeo de estados
    state_mapping = {
        0: "Solicitud realizada",
        1: "Aceptada",
        2: "Rechazada",
        3: "En progreso",
        4: "Completada"
    }

    # Filtrar solicitudes para el paciente
    requests = Request.query.filter_by(nhc_patient=nhc_patient).order_by(Request.date.desc()).all()
    request_list = [
        {
            'id': r.id,
            'nhc_patient': r.nhc_patient,
            'nanoid': r.nanoid,
            'date': r.date,
            'state': state_mapping.get(r.state, "Estado Desconocido")
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
    # Verificar si el usuario tiene una sesión activa y tiene el rol correcto
    role = session.get('user_role')

    # Si el usuario no es un admin (rol != 1), devolver un error de autorización
    if role != 1:
        return jsonify({'error': 'Unauthorized. Only admins can generate invitation codes.'}), 403

    # Generar el código de invitación solo si el rol es 1 (admin)
    invitation_code = generate_invitation_code()

    # Guardar el código en la base de datos
    new_invitation = Invitation(code=invitation_code, is_used=False)
    db.session.add(new_invitation)
    db.session.commit()

    return jsonify({'invitation_code': invitation_code}), 201


@main.route('/api/user/<int:user_id>', methods=['PUT'])
def update_user(user_id):

    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Verificar si el usuario tiene privilegios de administrador (opcional)
    if session.get('user_role') != 1:
        return jsonify({'message': 'No tienes permisos para acceder a esta información.'}), 403

    data = request.get_json()

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Actualizar los campos del usuario
    user.firstName = data.get('firstName', user.firstName)
    user.lastName = data.get('lastName', user.lastName)
    user.email = data.get('email', user.email)

    # Concatenar firstName y lastName para actualizar el username
    user.username = f"{user.firstName} {user.lastName}"

    try:
        db.session.commit()
        return jsonify({"message": "Usuario actualizado con éxito", "user": {
            "id": user.id,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "username": user.username,  # Este campo concatenado
            "email": user.email
        }}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@main.route('/api/request/<int:request_id>/download-files', methods=['GET'])
def download_files(request_id):
    # Obtener la solicitud y los archivos asociados desde la base de datos

    if 'user_email' not in session:
        return jsonify({'message': 'No estás autenticado.'}), 401

    # Verificar si el usuario tiene privilegios de administrador (opcional)
    if session.get('user_role') != 1:
        return jsonify({'message': 'No tienes permisos para acceder a esta información.'}), 403

    request_obj = Request.query.get(request_id)
    
    
    if not request_obj:
        return jsonify({"error": "Request not found"}), 404

    # Generar el contenido para el archivo de texto
    content = f"Paciente - {request_obj.nanoid}\n"
    content += f"Rama Lesion - por definir\n"
    content += f"PAS - {request_obj.pressure[:3]}\n"
    content += f"PAD - {request_obj.pressure[-3:]}\n"
    content += f"Hospital - por definir\n"
    content += f"Fecha - {request_obj.date.strftime('%d/%m/%y')}\n"

    # Obtener los archivos asociados a la solicitud
    files = File.query.filter_by(request_id=request_id).all()

    if not files:
        return jsonify({"error": "No hay archivos asociados a esta solicitud"}), 404

    # Crear un archivo ZIP en memoria
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        # Escribir las carpetas vacías en el ZIP
        zf.writestr('1_Datos/', '')
        zf.writestr('2_Geometria/', '')
        zf.writestr('3_Slicer/', '')
        zf.writestr('4_Informe/', '')
        zf.writestr('4_Informe/imagenes paciente/', '')

        # Escribir el archivo de texto directamente en el ZIP
        zf.writestr(f'4_Informe/paciente_{request_id}.txt', content)

        # Añadir el archivo .xlsx al ZIP
        xlsx_path = app.config['xlsx_template']
        zf.write(xlsx_path, os.path.join('4_Informe', os.path.basename(xlsx_path)))

        # Añadir los archivos asociados de la solicitud al ZIP
        for archivo in files:
            # Ruta del archivo en el servidor
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], archivo.filepath)
            
            # Añadir el archivo al ZIP dentro de la carpeta '1_Datos'
            zf.write(file_path, os.path.join('1_Datos', os.path.basename(file_path)))

    memory_file.seek(0)

    # Devolver el archivo ZIP al frontend
    return send_file(memory_file, download_name=f'files_request_{request_id}.zip', as_attachment=True)
