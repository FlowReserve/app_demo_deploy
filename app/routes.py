from flask import Blueprint, render_template, redirect, url_for, jsonify, send_file, request, session, current_app as app, send_from_directory
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
from datetime import datetime
import string
import random
import zipfile

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
            return jsonify(access_token=access_token, role=user.role), 200
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
            'firstName': user.firstName,
            'lastName': user.lastName,
            'email': user.email
        })
    return jsonify(users_list)  # Retorna la lista de usuarios en formato JSON

@main.route('/api/all-requests', methods=['GET'])
@cross_origin()
def get_all_requests():
    requests = Request.query.all()  # Consulta todos los usuarios en la base de datos

    requests = Request.query.all()

    request_list = [
        {
            'id': r.id,
            'nhc_patient': r.nhc_patient,
            'date': r.date.strftime('%d/%m/%y'),
            'state': r.state,  # Mapeo del estado a su string
            'pressure': r.pressure
        }
        for r in requests
    ]

    return jsonify(request_list), 200

@main.route('/api/update-request/<int:request_id>', methods=['PUT'])
@jwt_required()
def update_request(request_id):
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No se recibieron datos"}), 400

        print("Datos recibidos del frontend:", data)

        # Obtener el nuevo estado y otros campos
        new_state = data.get('state')
        nhc_patient = data.get('nhc_patient')

        if new_state is None or nhc_patient is None:
            return jsonify({"error": "Faltan campos obligatorios"}), 400


        # Buscar la solicitud por ID
        request_to_update = Request.query.get(request_id)

        if not request_to_update:
            return jsonify({"error": "Solicitud no encontrada"}), 404

        # Actualizar los datos de la solicitud
        request_to_update.state = int(new_state)
        request_to_update.nhc_patient = nhc_patient

        # Guardar cambios en la base de datos
        db.session.commit()

        return jsonify({"message": "Solicitud actualizada con éxito", "request": {
            "id": request_to_update.id,
            "state": request_to_update.state,
            "nhc_patient": request_to_update.nhc_patient,
            "date": request_to_update.date.isoformat()
        }}), 200

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
@jwt_required()
def update_request_state(request_id):
    try:
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
            'email': current_user.email,
            'role': current_user.role
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

@main.route('/api/user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
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
@jwt_required()
def download_files(request_id):
    # Obtener la solicitud y los archivos asociados desde la base de datos
    request = Request.query.get(request_id)

    if not request:
        return jsonify({"error": "Solicitud no encontrada"}), 404

    # Suponiendo que tienes un modelo "Archivo" relacionado con "Request"
    files = File.query.filter_by(request_id=request_id).all()

    if not files:
        return jsonify({"error": "No hay archivos asociados a esta solicitud"}), 404

    # Crear un archivo ZIP en memoria
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        for archivo in files:
            # Ruta del archivo en el servidor
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], archivo.filepath)
            zf.write(file_path, os.path.basename(file_path))  # Añadir archivo al ZIP

    memory_file.seek(0)

    # Devolver el archivo ZIP al frontend
    return send_file(memory_file, download_name='files_request_{}.zip'.format(request_id), as_attachment=True)