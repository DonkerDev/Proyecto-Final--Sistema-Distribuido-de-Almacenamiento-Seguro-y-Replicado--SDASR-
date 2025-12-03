@echo off
echo ====================================
echo DESPLIEGUE DEL SISTEMA DE ALMACENAMIENTO
echo ====================================

REM 1. Construir imagen Docker
echo Construyendo imagen Docker...
cd servidor
docker build -t servidor-almacenamiento:latest .
cd ..

REM 2. Iniciar Minikube (si no está corriendo)
echo Verificando Minikube...
minikube status > nul 2>&1
if errorlevel 1 (
    echo Iniciando Minikube...
    minikube start
) else (
    echo Minikube ya está corriendo
)

REM 3. Cargar imagen en Minikube
echo Cargando imagen en Minikube...
minikube image load servidor-almacenamiento:latest

REM 4. Desplegar en Kubernetes
echo Desplegando en Kubernetes...
kubectl apply -f kubernetes/

REM 5. Esperar a que los pods estén listos
echo Esperando a que los pods estén listos...
timeout /t 30 /nobreak > nul

REM 6. Mostrar estado
echo Estado del despliegue:
kubectl get pods
kubectl get services

echo.
echo ====================================
echo INSTRUCCIONES:
echo ====================================
echo 1. Para ejecutar el cliente:
echo    python cliente\cliente.py
echo.
echo 2. Para ver logs de los pods:
echo    kubectl logs -l app=almacenamiento
echo.
echo 3. Para acceder a un pod:
echo    kubectl exec -it ^<nombre-pod^> -- /bin/bash
echo.
echo 4. Para eliminar el despliegue:
echo    kubectl delete -f kubernetes/
echo ====================================
pause