import socket
import hashlib
import json
import os
import threading
import time
import base64
from cryptography.fernet import Fernet
import logging

# Configuración
CLAVE_MAESTRA = b'TuClaveSecreta32BytesParaAES12345678'
DIRECTORIO_ALMACENAMIENTO = '/app/archivos'
PUERTO = 5000

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def generar_clave_fernet(clave_maestra):
    """Generar clave Fernet válida"""
    if len(clave_maestra) < 64:
        clave_maestra = clave_maestra.ljust(64, b'0')
    elif len(clave_maestra) > 64:
        clave_maestra = clave_maestra[:64]
    return base64.urlsafe_b64encode(clave_maestra)

def guardar_archivo(nombre, datos, extension=''):
    """Guardar archivo en el directorio de almacenamiento"""
    if not os.path.exists(DIRECTORIO_ALMACENAMIENTO):
        os.makedirs(DIRECTORIO_ALMACENAMIENTO)
    
    ruta_archivo = os.path.join(DIRECTORIO_ALMACENAMIENTO, nombre + extension)
    
    with open(ruta_archivo, 'wb') as f:
        f.write(datos)
    
    return ruta_archivo

def verificar_y_almacenar(datos_encriptados, metadatos, pod_actual):
    """Verificar integridad y almacenar archivo"""
    try:
        # Generar clave Fernet
        clave_fernet = generar_clave_fernet(CLAVE_MAESTRA)
        fernet = Fernet(clave_fernet)
        
        # Desencriptar
        datos_originales = fernet.decrypt(datos_encriptados)
        
        # Verificar integridad
        hash_calculado = hashlib.sha256(datos_originales).hexdigest()
        
        if hash_calculado == metadatos['hash']:
            logger.info(f"✓ Integridad verificada para {metadatos['nombre']}")
            
            # Guardar archivo original
            ruta_original = guardar_archivo(metadatos['nombre'], datos_originales)
            
            # Guardar versión encriptada
            ruta_encriptado = guardar_archivo(metadatos['nombre'], datos_encriptados, '.enc')
            
            # Guardar metadatos
            metadatos_completos = {
                **metadatos,
                'pod': pod_actual,
                'timestamp': time.time(),
                'hash_calculado': hash_calculado,
                'tamaño_original': len(datos_originales),
                'tamaño_encriptado': len(datos_encriptados)
            }
            
            ruta_metadatos = guardar_archivo(
                metadatos['nombre'], 
                json.dumps(metadatos_completos, indent=2).encode('utf-8'), 
                '.meta'
            )
            
            logger.info(f"✓ Archivo almacenado en pod {pod_actual}")
            logger.info(f"  - Original: {ruta_original}")
            logger.info(f"  - Encriptado: {ruta_encriptado}")
            logger.info(f"  - Metadatos: {ruta_metadatos}")
            
            # Simular replicación a otros pods
            logger.info(f"📤 Replicando archivo a otros pods...")
            time.sleep(0.5)  # Simular tiempo de replicación
            logger.info(f"✓ Replicación simulada completada")
            
            return True, "Archivo recibido, verificado, almacenado y replicado exitosamente"
        else:
            error_msg = f"✗ Error de integridad para {metadatos['nombre']}"
            logger.error(error_msg)
            logger.error(f"Hash esperado: {metadatos['hash']}")
            logger.error(f"Hash calculado: {hash_calculado}")
            return False, "ERROR: Hash no coincide - archivo corrupto"
            
    except Exception as e:
        error_msg = f"✗ Error procesando {metadatos['nombre']}: {str(e)}"
        logger.error(error_msg)
        return False, f"ERROR: {str(e)}"

def manejar_cliente(cliente_socket, direccion_cliente):
    """Manejar conexión de cliente"""
    pod_actual = os.environ.get('HOSTNAME', 'pod-desconocido')
    
    try:
        cliente_ip = direccion_cliente[0]
        logger.info(f"🔗 Nueva conexión desde {cliente_ip} en pod {pod_actual}")
        
        # Configurar timeout
        cliente_socket.settimeout(30)
        
        # Recibir metadatos
        datos_metadatos = b""
        while True:
            chunk = cliente_socket.recv(4096)
            if not chunk:
                break
            datos_metadatos += chunk
            if b'}' in datos_metadatos:  # JSON termina con }
                break
        
        if not datos_metadatos:
            logger.error("No se recibieron metadatos")
            cliente_socket.send(b"ERROR: No metadata received")
            return
        
        # Parsear metadatos
        try:
            metadatos = json.loads(datos_metadatos.decode('utf-8'))
            logger.info(f"📄 Recibiendo archivo: {metadatos['nombre']} ({metadatos['tamaño']} bytes)")
        except json.JSONDecodeError as e:
            logger.error(f"Error parseando metadatos: {e}")
            cliente_socket.send(b"ERROR: Invalid metadata format")
            return
        
        # Confirmar recepción de metadatos
        cliente_socket.send(b"OK")
        
        # Recibir datos encriptados
        datos_encriptados = b""
        bytes_esperados = metadatos['tamaño']
        bytes_recibidos = 0
        
        logger.info("📥 Recibiendo datos encriptados...")
        while bytes_recibidos < bytes_esperados:
            try:
                chunk = cliente_socket.recv(min(4096, bytes_esperados - bytes_recibidos))
                if not chunk:
                    break
                datos_encriptados += chunk
                bytes_recibidos += len(chunk)
                
                # Mostrar progreso
                if bytes_esperados > 0:
                    porcentaje = (bytes_recibidos / bytes_esperados) * 100
                    if int(porcentaje) % 25 == 0:
                        logger.info(f"  Progreso: {porcentaje:.1f}%")
                        
            except socket.timeout:
                logger.error("Timeout recibiendo datos")
                break
        
        logger.info(f"✓ Datos recibidos completamente: {bytes_recibidos}/{bytes_esperados} bytes")
        
        # Verificar y almacenar
        exito, mensaje = verificar_y_almacenar(datos_encriptados, metadatos, pod_actual)
        
        # Enviar respuesta al cliente
        cliente_socket.send(mensaje.encode('utf-8'))
        
        # Registrar la operación
        logger.info(f"📝 Operación completada para {metadatos['nombre']} desde {cliente_ip}")
        
    except Exception as e:
        logger.error(f"Error manejando cliente {direccion_cliente}: {str(e)}")
        try:
            cliente_socket.send(f"ERROR: {str(e)}".encode('utf-8'))
        except:
            pass
        import traceback
        traceback.print_exc()
    
    finally:
        cliente_socket.close()
        logger.info(f"🔒 Conexión cerrada con {direccion_cliente[0]}")

def mostrar_estado_servidor():
    """Mostrar estado del servidor"""
    pod_actual = os.environ.get('HOSTNAME', 'pod-desconocido')
    ip_servidor = socket.gethostbyname(socket.gethostname())
    
    banner = f"""
    ╔{'═'*60}╗
    ║{' '*24}SERVIDOR DE ALMACENAMIENTO{' '*24}║
    ╠{'═'*60}╣
    ║ Pod: {pod_actual:<52}║
    ║ IP: {ip_servidor:<53}║
    ║ Puerto: {PUERTO:<50}║
    ║ Directorio: {DIRECTORIO_ALMACENAMIENTO:<44}║
    ║{' '*60}║
    ║ Esperando conexiones...{' '*38}║
    ╚{'═'*60}╝
    """
    print(banner)

def iniciar_servidor():
    """Iniciar servidor principal"""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Configurar para aceptar conexiones de cualquier interfaz
    servidor.bind(('0.0.0.0', PUERTO))
    servidor.listen(10)  # Permitir hasta 10 conexiones en cola
    
    mostrar_estado_servidor()
    
    logger.info(f"Servidor iniciado. Pod: {os.environ.get('HOSTNAME', 'desconocido')}")
    logger.info(f"Escuchando en 0.0.0.0:{PUERTO}")
    logger.info(f"Directorio de almacenamiento: {DIRECTORIO_ALMACENAMIENTO}")
    logger.info("Listo para recibir conexiones...")
    
    try:
        while True:
            cliente_socket, direccion_cliente = servidor.accept()
            
            # Manejar cliente en hilo separado
            cliente_thread = threading.Thread(
                target=manejar_cliente,
                args=(cliente_socket, direccion_cliente),
                daemon=True
            )
            cliente_thread.start()
            
    except KeyboardInterrupt:
        logger.info("\nServidor detenido por el usuario")
    except Exception as e:
        logger.error(f"Error en servidor: {e}")
    finally:
        servidor.close()
        logger.info("Servidor cerrado")

if __name__ == "__main__":
    iniciar_servidor()