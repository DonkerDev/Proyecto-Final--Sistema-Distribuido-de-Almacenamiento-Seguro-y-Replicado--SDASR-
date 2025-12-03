# Usar imagen base de Python
FROM python:3.9-slim

# Establecer directorio de trabajo
WORKDIR /app

# Copiar archivos de requisitos
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código del servidor
COPY servidor.py .

# Crear directorio para archivos
RUN mkdir -p /app/archivos

# Exponer puerto
EXPOSE 5000

# Comando para ejecutar el servidor
CMD ["python", "servidor.py"]