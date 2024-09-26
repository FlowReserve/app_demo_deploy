# Usamos una imagen base de Python
FROM python:3.9-slim

# Establecemos el directorio de trabajo en /app
WORKDIR /app

# Copiamos el archivo de requisitos y lo instalamos
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos todo el contenido de la aplicación al contenedor
COPY . .

# Exponemos el puerto en el que Gunicorn estará escuchando
EXPOSE 5000

# Comando para ejecutar Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]
