# Usamos una imagen base de Python con Alpine Linux
FROM python:3.11-alpine

# Instalar dependencias del sistema necesarias para la compilación y MySQL
RUN apk update && apk add --no-cache \
    mariadb-connector-c-dev \
    gcc \
    g++ \
    libffi-dev \
    musl-dev \
    openssl-dev \
    make \
    && rm -rf /var/cache/apk/*

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