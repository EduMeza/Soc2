"""Isolated real-browser E2E plus PowerShell start/stop health and PID verification."""
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='soc2-e2e-') as directory:
        temp = Path(directory)
        env = os.environ.copy()
        username,password,new_password = 'e2e_'+secrets.token_hex(6),secrets.token_urlsafe(18),secrets.token_urlsafe(18)
        env.update(APP_ENV='test', DATABASE_URL='sqlite:///'+(temp/'soc.db').as_posix(),
            JWT_SECRET=secrets.token_urlsafe(48), INITIAL_ADMIN_USERNAME=username, INITIAL_ADMIN_PASSWORD=password,
            SOC_TEST_OUTPUT_DIR=str(temp/'output'), SOC_TEST_RUNTIME_DIR=str(temp/'runtime'),
            SOC_BACKEND_PORT='18000', SOC_FRONTEND_PORT='15173',
            CORS_ORIGINS='http://localhost:15173', VITE_API_BASE_URL='http://127.0.0.1:18000/api',
            E2E_USERNAME=username,E2E_PASSWORD=password,E2E_NEW_PASSWORD=new_password,E2E_BASE_URL='http://localhost:15173')
        try:
            command = ['powershell.exe','-NoProfile','-File',str(ROOT/'scripts/start_soc.ps1')]
            # Windows child processes can inherit pipe handles; use a log file
            # instead of PIPE so communicate() cannot wait for a live server.
            with (temp/'startup.log').open('w+',encoding='utf-8',errors='replace') as log:
                started = subprocess.run(command,env=env,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=120)
                log.seek(0)
                output = log.read()
                print(output,flush=True)
                started.check_returncode()
                assert password not in output and username not in output
            with (temp/'occupied.log').open('w+',encoding='utf-8',errors='replace') as log:
                occupied = subprocess.run(command,env=env,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=30)
                log.seek(0)
                assert occupied.returncode != 0 and 'ocupado' in log.read()
            print('Occupied-port guard: non-zero exit; credentials absent from startup output.')
            result = subprocess.run(['npx.cmd','playwright','test'],env=env,cwd=ROOT/'frontend')
        finally:
            stopped = subprocess.run(['powershell.exe','-NoProfile','-File',str(ROOT/'scripts/stop_soc.ps1')],env=env,cwd=ROOT)
            if stopped.returncode:
                raise RuntimeError('Falló stop_soc: revisar PIDs del entorno de prueba')
        raise SystemExit(result.returncode)
