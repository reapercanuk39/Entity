import os, json, time, logging
logger = logging.getLogger(__name__)

# try to use cryptography Fernet, fall back to simple XOR if unavailable
try:
    from cryptography.fernet import Fernet
    _HAS_FERNET = True
except Exception:
    _HAS_FERNET = False

# try paramiko
try:
    import paramiko
    _HAS_PARAMIKO = True
except Exception:
    _HAS_PARAMIKO = False

CRED_PATH = os.path.join(os.path.dirname(__file__), 'credentials.json.enc')

def _derive_fernet_key(passphrase: str) -> bytes:
    # derive 32-byte key via sha256 and base64-urlsafe
    import hashlib, base64
    k = hashlib.sha256(passphrase.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(k)

def save_credentials(creds: dict, passphrase: str) -> None:
    os.makedirs(os.path.dirname(CRED_PATH), exist_ok=True)
    if _HAS_FERNET:
        key = _derive_fernet_key(passphrase)
        f = Fernet(key)
        token = f.encrypt(json.dumps(creds).encode('utf-8'))
        with open(CRED_PATH, 'wb') as fh:
            fh.write(token)
    else:
        # fallback simple XOR
        from base64 import b64encode
        key = passphrase.encode('utf-8')
        data = json.dumps(creds).encode('utf-8')
        out = bytearray()
        for i,b in enumerate(data):
            out.append(b ^ key[i % len(key)])
        with open(CRED_PATH, 'wb') as fh:
            fh.write(b64encode(bytes(out)))

def load_credentials(passphrase: str) -> dict:
    if not os.path.exists(CRED_PATH):
        return {}
    data = open(CRED_PATH, 'rb').read()
    if _HAS_FERNET:
        try:
            key = _derive_fernet_key(passphrase)
            f = Fernet(key)
            plain = f.decrypt(data)
            return json.loads(plain.decode('utf-8'))
        except Exception:
            raise
    else:
        from base64 import b64decode
        key = passphrase.encode('utf-8')
        raw = b64decode(data)
        out = bytearray()
        for i,b in enumerate(raw):
            out.append(b ^ key[i % len(key)])
        return json.loads(bytes(out).decode('utf-8'))

def add_credential(name: str, username: str, password: str = None, key_path: str = None, passphrase: str = None):
    if not passphrase:
        raise ValueError('passphrase required')
    creds = {}
    try:
        creds = load_credentials(passphrase)
    except Exception:
        creds = {}
    creds[name] = {'username': username, 'password': password, 'key_path': key_path}
    save_credentials(creds, passphrase)

def list_credentials(passphrase: str) -> dict:
    return load_credentials(passphrase)

def remove_credential(name: str, passphrase: str) -> bool:
    creds = load_credentials(passphrase)
    if name in creds:
        del creds[name]
        save_credentials(creds, passphrase)
        return True
    return False


def deploy_agent(ip: str, username: str, password: str = None, key_path: str = None, agent_local_path: str = None, sudo: bool = True, timeout: int = 10, key_content: str = None, tunnel: dict = None):
    """Deploy agent script to remote host via SSH/SFTP and attempt to install a systemd unit.
    Optionally upload a private key content and install a reverse SSH tunnel unit (tunnel dict expected with keys relay_host, relay_port, relay_user, remote_port).
    Returns dict with results. Requires explicit operator authorization for each target.
    """
    res = {'ip': ip, 'uploaded': False, 'unit_installed': False, 'tunnel_installed': False, 'errors': []}
    if not _HAS_PARAMIKO:
        res['errors'].append('paramiko_missing')
        return res
    if not agent_local_path or not os.path.exists(agent_local_path):
        res['errors'].append('agent_missing')
        return res
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path:
            client.connect(ip, username=username, key_filename=key_path, timeout=timeout)
        else:
            client.connect(ip, username=username, password=password, timeout=timeout)
        sftp = client.open_sftp()
        remote_tmp = f'/tmp/queen_agent_{int(time.time())}.sh'
        sftp.put(agent_local_path, remote_tmp)
        sftp.chmod(remote_tmp, 0o755)
        res['uploaded'] = True
        # prepare systemd unit content for agent
        unit = f'''[Unit]\nDescription=Queen Agent (deployed)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/queen_agent.sh\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n'''
        # move agent to /usr/local/bin and install unit
        cmds = []
        cmds.append(f'sudo mv {remote_tmp} /usr/local/bin/queen_agent.sh' if sudo else f'mv {remote_tmp} /usr/local/bin/queen_agent.sh')
        cmds.append('sudo chmod 755 /usr/local/bin/queen_agent.sh' if sudo else 'chmod 755 /usr/local/bin/queen_agent.sh')
        # upload unit via echo (safer than sftp to /etc)
        cmds.append('sudo bash -lc "cat > /etc/systemd/system/queen_agent.service <<\'EOL\'\n' + unit + '\nEOL\'"' if sudo else 'bash -lc "cat > /etc/systemd/system/queen_agent.service <<\'EOL\'\n' + unit + '\nEOL\'"')
        cmds.append('sudo systemctl daemon-reload' if sudo else 'systemctl daemon-reload')
        cmds.append('sudo systemctl enable --now queen_agent.service' if sudo else 'systemctl enable --now queen_agent.service')
        # handle optional tunnel installation
        if tunnel and isinstance(tunnel, dict) and key_content:
            try:
                # write key content to remote temporary file
                remote_key_tmp = f'/tmp/queen_tunnel_key_{int(time.time())}'
                with sftp.open(remote_key_tmp, 'w') as kf:
                    kf.write(key_content)
                sftp.chmod(remote_key_tmp, 0o600)
                # move key into /usr/local/bin and set perms
                cmds.append('sudo mv {} /usr/local/bin/queen_tunnel_key'.format(remote_key_tmp) if sudo else 'mv {} /usr/local/bin/queen_tunnel_key'.format(remote_key_tmp))
                cmds.append('sudo chmod 600 /usr/local/bin/queen_tunnel_key' if sudo else 'chmod 600 /usr/local/bin/queen_tunnel_key')
                # generate tunnel unit
                relay_host = tunnel.get('relay_host')
                relay_port = int(tunnel.get('relay_port', 22))
                relay_user = tunnel.get('relay_user')
                remote_port = int(tunnel.get('remote_port', 2222))
                ssh_cmd = f"/usr/bin/ssh -o ServerAliveInterval=60 -o ExitOnForwardFailure=yes -N -R {remote_port}:localhost:22 -i /usr/local/bin/queen_tunnel_key -p {relay_port} {relay_user}@{relay_host}"
                tunnel_unit = f'''[Unit]\nDescription=Queen Tunnel (reverse SSH)\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={ssh_cmd}\nRestart=always\nRestartSec=10\nUser={username}\n\n[Install]\nWantedBy=multi-user.target\n'''
                cmds.append('sudo bash -lc "cat > /etc/systemd/system/queen_tunnel.service <<\'EOL\'\n' + tunnel_unit + '\nEOL\'"' if sudo else 'bash -lc "cat > /etc/systemd/system/queen_tunnel.service <<\'EOL\'\n' + tunnel_unit + '\nEOL\'"')
                cmds.append('sudo systemctl daemon-reload' if sudo else 'systemctl daemon-reload')
                cmds.append('sudo systemctl enable --now queen_tunnel.service' if sudo else 'systemctl enable --now queen_tunnel.service')
                res['tunnel_requested'] = True
            except Exception as e:
                res['errors'].append(f'tunnel_setup_failed:{e}')
        # execute commands
        for cmd in cmds:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            if err:
                res['errors'].append({'cmd': cmd, 'err': err})
        # close
        sftp.close()
        client.close()
        if not any(('errors' in res and res['errors'])):
            res['unit_installed'] = True
            if res.get('tunnel_requested') and not res.get('errors'):
                res['tunnel_installed'] = True
    except Exception as e:
        logger.exception('Deploy failed')
        res['errors'].append(str(e))
    return res
