import multiprocessing
import os

# Bind via Unix socket para mejor rendimiento
bind = "unix:/run/gunicorn/volcanmanagerapi.sock"

# Número óptimo de workers
workers = multiprocessing.cpu_count() * 2 + 1

# Worker compatible con ASGI (Django asgi.py)
worker_class = "uvicorn.workers.UvicornWorker"

# Nivel de logs
loglevel = "info"

# Un solo archivo de log compartido (como antes con uWSGI)
log_file = "/var/log/gunicorn/volcan-volcanmanagerapi.log"
accesslog = log_file
errorlog = log_file
capture_output = True

# Asegura que el archivo de log exista y tenga permisos adecuados
os.makedirs(os.path.dirname(log_file), exist_ok=True)
open(log_file, "a").close()
os.chmod(log_file, 0o664)
os.chown(log_file, os.getuid(), os.getgid())


