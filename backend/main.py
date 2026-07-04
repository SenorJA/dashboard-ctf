from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import paramiko
import asyncio
import os

app = FastAPI()

# Configuramos las rutas de los archivos estáticos
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # Credenciales de tu Kali
    KALI_IP = "192.168.1.138"
    KALI_USER = "javi"
    KALI_PASS = "javi" 

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        await websocket.send_text("[*] Conectando a Kali por SSH...")
        # Conexión SSH sincrona (la corremos en un hilo para no bloquear FastAPI)
        await asyncio.to_thread(ssh.connect, KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=5)
        await websocket.send_text("[+] Conexión establecida con éxito.\n")

        while True:
            # Esperamos comandos desde el frontend web
            comando = await websocket.receive_text()
            await websocket.send_text(f"javi@kali:~$ {comando}")
            
            # Ejecutamos el comando
            stdin, stdout, stderr = ssh.exec_command(comando)
            
            # Leemos la salida
            salida = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if salida:
                await websocket.send_text(salida)
            if error:
                await websocket.send_text(f"[ERROR]: {error}")

    except WebSocketDisconnect:
        print("Cliente web desconectado")
    except Exception as e:
        await websocket.send_text(f"[!] Error de conexión: {str(e)}")
    finally:
        ssh.close()