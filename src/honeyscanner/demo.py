import socket
import paramiko
import time


def connect_ssh() -> paramiko.Channel | None:
    try:
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _socket.connect(('localhost', 2222))
        transport = paramiko.Transport(_socket)
        sec_opts: paramiko.SecurityOptions = transport.get_security_options()
        sec_opts.kex = ['diffie-hellman-group1-sha1']
        sec_opts.key_types = ['ssh-dss', 'ssh-rsa']
        transport.start_client()
        transport.auth_password('root', '123456')

        while not transport.is_authenticated():
            time.sleep(1)

            chan: paramiko.Channel = transport.open_session()
            chan.get_pty()
            chan.invoke_shell()
            return chan
    except Exception as e:
        print(f"Error while connecting socket: {e}")
        
    

print(connect_ssh())