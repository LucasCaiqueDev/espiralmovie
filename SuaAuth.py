import urllib.request
import json
import hashlib
import platform
import subprocess
import sys
import ctypes
import time

class SuaAuthApi:
    def __init__(self, app_id, secret, version="1.0"):
        self.app_id = app_id
        self.secret = secret
        self.version = version
        self.api_url = "https://espiralauth.discloud.app/api/client/auth" # Troque pelo seu domínio na Discloud
        self.user_data = None
        
        # Security Check on Init
        if self._check_security():
            sys.exit(1)

    def _check_security(self):
        """
        Executa verificações básicas de ambiente.
        Retorna True se uma ameaça for detectada.
        """
        # 1. Python Debugger (sys.gettrace)
        if sys.gettrace() is not None:
            return True
            
        # 2. Windows Debugger (IsDebuggerPresent)
        if platform.system() == "Windows":
            try:
                windll = getattr(ctypes, 'windll', None)
                if windll and windll.kernel32.IsDebuggerPresent():
                    return True
            except:
                pass
                
        # 3. Timing Attack / Latency Check (Simple)
        start = time.time()
        a = 0
        for i in range(10000):
            a += i
        end = time.time()
        # Se demorar muito mais que o normal para uma operação simples, pode estar sendo analisado passo a passo
        if (end - start) > 0.5: 
            return True
            
        return False

    def get_hwid(self):
        # Gera um HWID baseado no nome do PC e processador
        hwid_str = f"{platform.node()}-{platform.processor()}-{platform.machine()}"
        return hashlib.sha256(hwid_str.encode()).hexdigest()

    def _send_request(self, data):
        try:
            req = urllib.request.Request(
                self.api_url, 
                data=json.dumps(data).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as e:
            return {"success": False, "message": f"Erro de conexão: {str(e)}"}

    def init(self):
        data = {
            "type": "init",
            "appId": self.app_id,
            "secret": self.secret
        }
        return self._send_request(data)

    def login(self, username, password):
        data = {
            "type": "login",
            "appId": self.app_id,
            "secret": self.secret,
            "username": username,
            "password": password,
            "hwid": self.get_hwid()
        }
        res = self._send_request(data)
        if res.get("success"):
            self.user_data = res.get("info")
        return res

    def register(self, username, password, license_key):
        data = {
            "type": "register",
            "appId": self.app_id,
            "secret": self.secret,
            "username": username,
            "password": password,
            "key": license_key,
            "hwid": self.get_hwid()
        }
        return self._send_request(data)

    def authenticate(self, key):
        data = {
            "type": "license",
            "appId": self.app_id,
            "secret": self.secret,
            "key": key,
            "hwid": self.get_hwid()
        }
        res = self._send_request(data)
        if res.get("success"):
            self.user_data = res.get("info")
        return res
