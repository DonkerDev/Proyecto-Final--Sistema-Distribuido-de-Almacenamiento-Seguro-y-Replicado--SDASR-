import socket
import hashlib
import os
import json
import base64
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox

# Clave AES pre-compartida (debe ser exactamente 32 bytes)
CLAVE_MAESTRA = b'TuClaveSecreta32BytesParaAES12345678'  # 32 bytes

def generar_clave_fernet(clave_maestra):
    """Generar una clave Fernet válida (base64 de 32 bytes)"""
    # Asegurar que la clave tenga exactamente 32 bytes
    if len(clave_maestra) != 32:
        clave_maestra = clave_maestra[:32].ljust(32, b'0')
    
    # Convertir a base64 para Fernet
    return base64.urlsafe_b64encode(clave_maestra)

def encriptar_archivo(ruta_archivo, clave_fernet):
    """Encriptar un archivo usando Fernet (AES en modo CBC)"""
    with open(ruta_archivo, 'rb') as file:
        datos = file.read()
    
    # Calcular hash del archivo original
    hash_original = hashlib.sha256(datos).hexdigest()
    print(f"Hash SHA-256 calculado: {hash_original}")
    
    # Encriptar datos
    fernet = Fernet(clave_fernet)
    datos_encriptados = fernet.encrypt(datos)
    
    print(f"Archivo encriptado. Tamaño original: {len(datos)} bytes")
    print(f"Tamaño encriptado: {len(datos_encriptados)} bytes")
    
    return datos_encriptados, hash_original

def seleccionar_archivo():
    """Interfaz para seleccionar archivo"""
    root = tk.Tk()
    root.withdraw()  # Ocultar ventana principal
    
    archivo = filedialog.askopenfilename(
        title="Seleccionar archivo para subir",
        filetypes=[("Todos los archivos", "*.*")]
    )
    
    root.destroy()
    return archivo

def mostrar_resumen(nombre_archivo, hash_original, datos_encriptados):
    """Mostrar resumen de la operación"""
    resumen = f"""
    RESUMEN DE OPERACIÓN:
    ---------------------
    Nombre archivo: {nombre_archivo}
    Hash SHA-256: {hash_original}
    Tamaño encriptado: {len(datos_encriptados)} bytes
    Clave usada: {CLAVE_MAESTRA[:16].decode('utf-8', errors='ignore')}...
    
    El archivo ha sido:
    1. Leído del disco ✓
    2. Hasheado (SHA-256) ✓
    3. Encriptado (AES-256) ✓
    4. Preparado para envío ✓
    """
    print(resumen)

def enviar_archivo(host='localhost', port=30007):
    """Función principal para enviar archivo al servidor"""
    try:
        # Seleccionar archivo
        ruta_archivo = seleccionar_archivo()
        if not ruta_archivo:
            print("No se seleccionó ningún archivo.")
            return
        
        nombre_archivo = os.path.basename(ruta_archivo)
        print(f"\n{'='*50}")
        print(f"PROCESANDO ARCHIVO: {nombre_archivo}")
        print(f"Ruta: {ruta_archivo}")
        print(f"Tamaño original: {os.path.getsize(ruta_archivo)} bytes")
        print(f"{'='*50}")
        
        # Generar clave Fernet
        print("\nGenerando clave de encriptación...")
        clave_fernet = generar_clave_fernet(CLAVE_MAESTRA)
        print(f"Clave Fernet generada: {len(clave_fernet)} bytes")
        
        # Encriptar archivo y calcular hash
        print("\nEncriptando archivo...")
        datos_encriptados, hash_original = encriptar_archivo(ruta_archivo, clave_fernet)
        
        # Mostrar resumen
        mostrar_resumen(nombre_archivo, hash_original, datos_encriptados)
        
        # Crear metadatos
        metadatos = {
            'nombre': nombre_archivo,
            'hash': hash_original,
            'tamaño': len(datos_encriptados),
            #'clave': CLAVE_MAESTRA.decode('utf-8', errors='ignore')  # Solo para demostración
        }
        
        # Conectar al servidor
        print(f"\nConectando al servidor {host}:{port}...")#conexion mediante iop y puerto que activa minikube
                                                        #con:  minikube service servicio-almacenamiento --url
        
        cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente_socket.settimeout(30)  # Espera un tiempo de 30 segundos para la conexion
        
        #manejo de excepciones en caso de que no halla conexion dentro del tiempo establecidio
        try:
            cliente_socket.connect((host, port))
            print("✓ Conexión establecida con el servidor")
        except Exception as e:
            print(f"✗ Error conectando al servidor: {e}")
            print("\nPosibles soluciones:")
            print("1. Verifica que Minikube esté corriendo: minikube status")
            print("2. Verifica el servicio: kubectl get services")
            print("3. Prueba con localhost si estás en Minikube")
            return
        
        # Enviar metadatos
        print("Enviando metadatos...")
        cliente_socket.send(json.dumps(metadatos).encode('utf-8'))
        
        # Esperar ACK del servidor
        ack = cliente_socket.recv(1024)
        if ack == b"OK":
            print("✓ Metadatos recibidos por el servidor")
        else:
            print("✗ Error en confirmación de metadatos")
            return
        
        # Enviar datos encriptados
        print("Enviando archivo encriptado...")
        bytes_enviados = 0
        chunk_size = 4096
        
        with open(ruta_archivo + '.enc', 'wb') as f:  # Guardar copia encriptada localmente
            f.write(datos_encriptados)
        
        # Enviar en chunks
        while bytes_enviados < len(datos_encriptados):
            chunk = datos_encriptados[bytes_enviados:bytes_enviados + chunk_size]
            cliente_socket.send(chunk)
            bytes_enviados += len(chunk)
            
            # Mostrar progreso
            porcentaje = (bytes_enviados / len(datos_encriptados)) * 100
            print(f"Progreso: {porcentaje:.1f}% ({bytes_enviados}/{len(datos_encriptados)} bytes)", end='\r')
        
        print(f"\n✓ Archivo enviado completamente: {bytes_enviados} bytes")
        
        # Recibir confirmación final
        respuesta = cliente_socket.recv(4096).decode('utf-8')
        print(f"\nRespuesta del servidor: {respuesta}")
        
        cliente_socket.close()
        
        # Mostrar mensaje final
        print(f"\n{'='*50}")
        print("TRANSFERENCIA COMPLETADA EXITOSAMENTE!")
        print(f"{'='*50}")
        
        # Guardar información de auditoría
        with open('auditoria.txt', 'a') as audit:
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            audit.write(f"[{timestamp}] {nombre_archivo} | Hash: {hash_original} | Estado: {respuesta}\n")
        
        if messagebox.askyesno("Éxito", "Archivo subido exitosamente. ¿Ver detalles completos?"):
            print(f"\nDETALLES COMPLETOS:")
            print(f"- Nombre archivo: {nombre_archivo}")
            print(f"- Ruta local: {ruta_archivo}")
            print(f"- Hash SHA-256: {hash_original}")
            print(f"- Tamaño original: {os.path.getsize(ruta_archivo)} bytes")
            print(f"- Tamaño encriptado: {len(datos_encriptados)} bytes")
            print(f"- Copia encriptada guardada en: {ruta_archivo}.enc")
            print(f"- Auditoría guardada en: auditoria.txt")
        
    except socket.timeout:
        print("\n✗ Timeout: El servidor no respondió a tiempo")
        messagebox.showerror("Timeout", "El servidor no respondió dentro del tiempo esperado")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        messagebox.showerror("Error", f"No se pudo subir el archivo: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("="*60)
    print("CLIENTE DE ALMACENAMIENTO SEGURO")
    print("Con encriptación AES-256 y verificación SHA-256")
    print("="*60)
    
    # Preguntar por host y puerto
    import sys
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = input("Ingresa la IP del servidor (localhost para Minikube): ") or 'localhost'
    
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port_input = input("Ingresa el puerto (30007 para NodePort): ") or '30007'
        port = int(port_input)
    
    print(f"\nConfiguración:")
    print(f"- Servidor: {host}:{port}")
    print(f"- Clave de encriptación: {CLAVE_MAESTRA[:16].decode('utf-8', errors='ignore')}...")
    print()
    
    while True:
        enviar_archivo(host, port)
        continuar = input("\n¿Deseas subir otro archivo? (s/n): ")
        if continuar.lower() != 's':
            break
    
    print("\nGracias por usar el cliente de almacenamiento seguro!")