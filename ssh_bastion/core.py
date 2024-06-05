import socket, threading
import re
import os, pwd
import time, random
import paramiko, subprocess, pty, pam
import struct, fcntl, termios

from .config import COMMON_NAME, Config
from .misc import set_cgroup, set_cmdline

Config = Config()


class SSHServer(paramiko.ServerInterface):
    def __init__(self, transport):
        self.protocal = transport
        self.username = None
        self.password = ''
        self.retry = 0
        self.cooldown = 1
        self.usePty = False
        self.term = ()
        self.pty_master_fd = None
        self.pty_slave_fd = None
        self.useShell = False
        self.useExec = False
        self.useSubsystem = False
        self.something = threading.Event()
        self.subSysDone = threading.Event()
        self.trans_user = None
        self.trans_pass = ''
        self.trans_server = None
        self.trans_port = 22
        self.client_sock = None
        self.client_protocol = None
        self.client_channel = None

    def check_channel_request(self, kind, _):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED

    def parse_username(self, username):
        # '`"$\;&<>|(){} are not allowed in username in openssh
        _reg = re.search(r'(.*?)(?<!%)#(.*)', username)
        if _reg:
            # >user<#user@ip:port
            _u, _trans = _reg.groups()
            self.username = re.sub(r'%(.)', r'\1', _u).strip()
            # user#>user@ip:port<
            _reg_trans = re.search(r'(.*?)(?<!%)@(.*)', _trans)
            if _reg_trans:
                _trans_u, _trans_server = _reg_trans.groups()
                # user#>user<@ip:port
                self.trans_user = re.sub(r'%(.)', r'\1', _trans_u).strip()
                # user#user@>ip<:port
                _trans_ip = re.search(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', _trans_server)
                if _trans_ip:
                    _octet1 = int(_trans_ip.group(1))
                    _octet2 = int(_trans_ip.group(2))
                    _octet3 = int(_trans_ip.group(3))
                    _octet4 = int(_trans_ip.group(4))
                    if _octet1 >= 1 and _octet1 <= 223 and\
                            _octet2 >= 0 and _octet2 <= 255 and\
                            _octet3 >= 0 and _octet3 <= 255 and\
                            _octet4 >= 0 and _octet4 <= 254:
                        self.trans_server = _trans_ip.group()
                # user#user@ip:>port<
                _trans_port = re.search(r'(?<=:)\d{1,5}$', _trans_server)
                if _trans_port:
                    _trans_port = int(_trans_port.group())
                    if _trans_port >= 1 and _trans_port <= 65535:
                        self.trans_port = _trans_port
        else:
            self.username = re.sub(r'%(.)', r'\1', username).strip()
        print('[D] username:', self.username)
        print('[D] trans_user:', self.trans_user)
        print('[D] trans_server:', self.trans_server)
        print('[D] trans_port:', self.trans_port)

    def parse_password(self, password):
        _reg = re.search(r'(.*?)(?<!%)#(.*)', password)
        if _reg:
            _p, _trans_p = _reg.groups()
            self.password = re.sub(r'%(.)', r'\1', _p)
            self.trans_pass = re.sub(r'%(.)', r'\1', _trans_p)
        else:
            self.password = re.sub(r'%(.)', r'\1', password)
        # print('[D] password:', self.password)
        # print('[D] trans_pass:', self.trans_pass)

    def auth_password(self, mode):
        def __fail():
            if self.retry >= Config.LOGIN_RETRY:
                print('[D] auth_password retry limit reached.')
                self.protocal.lock.acquire()
                try:
                    self.protocal.server_accept_cv.notify()
                except Exception:
                    pass
                # disconnect immediately
                self.protocal.sock.shutdown(socket.SHUT_RDWR)
                self.protocal.lock.release()
                return
            if mode != 'none':
                _wait = self.cooldown + random.uniform(0, self.cooldown)
                print('[D] auth_password penalty:', _wait)
                time.sleep(_wait)
                self.cooldown *= 2
                self.retry += 1

        if self.username == 'root':
            pass
        if self.password == '':
            pass

        try:
            _auth = pam.authenticate(self.username, self.password)
        except Exception as e:
            print('[D] auth_password:', e)
            __fail()
            return False
        if _auth:
            print('[I] Logged in:', self.username)
            if self.trans_user and self.trans_server:
                try:
                    self.client_sock = socket.create_connection((self.trans_server, self.trans_port), timeout=10.0)
                except Exception as e:
                    print('[D] client_sock:', e)
                    __fail()
                    return False

                self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                self.client_protocol = paramiko.Transport(self.client_sock)
                try:
                    self.client_protocol.connect(username=self.trans_user, password=self.trans_pass)
                    self.client_channel = self.client_protocol.open_session()
                except Exception as e:
                    print('[D] client_protocol:', e)
                    self.client_sock.shutdown(socket.SHUT_RDWR)
                    self.client_protocol.close()
                    self.client_protocol = None
                    __fail()
                    return False
            return True
        else:
            print('[D] password wrong.')
            __fail()
            return False

    def check_auth_none(self, username):
        print('[D] auth_none')
        self.parse_username(str(username))
        self.password = ''
        self.trans_pass = ''
        if self.auth_password('none'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        print('[D] auth_password')
        self.parse_password(str(password))
        if self.auth_password('password'):
            self.password = ''
            self.trans_pass = ''
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        print('[D] pty_request:', term, width, height, pixelwidth, pixelheight)
        try:
            _term = term.decode()
            int(width)
            int(height)
            int(pixelwidth)
            int(pixelheight)
        except Exception:
            return False
        self.usePty = True
        self.term = (_term, width, height, pixelwidth, pixelheight)
        if self.client_channel:
            self.client_channel.get_pty(*self.term)
        else:
            self.pty_master_fd, self.pty_slave_fd = pty.openpty()
            self.set_pty_size(width, height, pixelwidth, pixelheight)
        return True

    def check_channel_shell_request(self, _):
        print('[D] useShell')
        self.useShell = True
        self.something.set()
        return True

    def check_channel_exec_request(self, channel, command):
        print('[D] exec_request:', command)
        self.useExec = command
        self.something.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        if self.trans_user and self.trans_server and name == 'sftp':
            channel.get_transport().set_subsystem_handler(name, SFTPSubsys)
        if super().check_channel_subsystem_request(channel, name):
            print('[D] subsystem_request:', name)
            self.useSubsystem = name
            self.something.set()
            return True
        print('[D] subsystem_request denied:', name)
        return False

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        try:
            int(width)
            int(height)
            int(pixelwidth)
            int(pixelheight)
        except Exception:
            return False
        print('[D] window_change_request:', width, height, pixelwidth, pixelheight)
        self.set_pty_size(width, height, pixelwidth, pixelheight)
        return True

    def set_pty_size(self, width, height, pixelwidth, pixelheight):
        if self.pty_master_fd:
            winsize = struct.pack('HHHH', height, width, pixelwidth, pixelheight)
            fcntl.ioctl(self.pty_master_fd, termios.TIOCSWINSZ, winsize)
        elif self.client_channel:
            self.client_channel.resize_pty(width, height, pixelwidth, pixelheight)


class SFTPSubsys(paramiko.SubsystemHandler):
    def __init__(self, channel: paramiko.Channel, name: str, server: paramiko.ServerInterface) -> None:
        super().__init__(channel, name, server)
        self.__server = server

    def start_subsystem(self, name, transport, channel):
        print('[D] start_subsystem:', name)
        if self.__server.client_channel:
            try:
                self.__server.client_channel.invoke_subsystem('sftp')
            except Exception as e:
                self.__server.client_sock.shutdown(socket.SHUT_RDWR)
                self.__server.client_protocol.close()
                self.__server.client_channel = None
                channel.sendall(f'Failed to start sftp subsystem on {self._server.trans_server}:{self._server.trans_port}: {e}\r\n'.encode())
                channel.close()
            _tIn = threading.Thread(target=handle_input, args=(self.__server.client_channel, None, channel))
            _tOut = threading.Thread(target=handle_output, args=(self.__server.client_channel, None, channel))
        else:
            _sftp = subprocess.Popen(
                ['/usr/libexec/openssh/sftp-server', '-l', 'INFO'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            _tIn = threading.Thread(target=handle_input, args=(_sftp, _sftp.stdin.fileno(), channel))
            _tOut = threading.Thread(target=handle_output, args=(_sftp, _sftp.stdout.fileno(), channel))
        _tIn.start()
        _tOut.start()
        if not self.__server.client_channel:
            _sftp.wait()
        _tIn.join()
        _tOut.join()
        self.__server.subSysDone.set()


def handle_input(child: subprocess.Popen | paramiko.Channel, fd, channel):
    if fd:
        _f = open(fd, 'wb')
        while True:
            _d = channel.recv(2097152)
            # print('[D] Input:', _d)
            if len(_d) == 0:
                print('[D] Input closed')
                if child.poll() is None:
                    child.kill()
                break
            _f.write(_d)
            _f.flush()
    else:
        while True:
            _d = channel.recv(2097152)
            # print('[D] Input:', _d)
            if len(_d) == 0:
                print('[D] Input closed')
                child.close()
                break
            child.sendall(_d)


def handle_output(child: subprocess.Popen | paramiko.Channel, fd, channel):
    if fd:
        _f = open(fd, 'rb')
        while True:
            try:
                _o = _f.read1()
            except Exception:
                _o = b''
            # print('[D] Output:', _o)
            if len(_o) == 0:
                print('[D] Output closed')
                try:
                    channel.send_exit_status(child.wait())
                    print('[D] Exit code:', child.returncode)
                except Exception:
                    pass
                channel.close()
                break
            try:
                channel.sendall(_o)
            except EOFError:
                break
    else:
        while True:
            _o = child.recv(2097152)
            # print('[D] Output:', _o)
            if len(_o) == 0:
                print('[D] Output closed')
                try:
                    _return = child.recv_exit_status()
                    channel.send_exit_status(_return)
                    print('[D] Exit code:', _return)
                except Exception:
                    pass
                channel.close()
                break
            try:
                channel.sendall(_o)
            except EOFError:
                break


def handle_connection(conn: socket.socket, addr):
    set_cgroup(os.getpid())
    set_cmdline(f'{COMMON_NAME} [session]: {addr[0]}:{addr[1]}')
    protocol = paramiko.Transport(conn)
    try:
        protocol.add_server_key(paramiko.RSAKey(filename=f'/etc/ssh/{Config.RSA_KEY}'))
    except Exception:
        _selfKey = f'{os.path.dirname(os.path.abspath(__file__))}/{Config.RSA_KEY}'
        try:
            protocol.add_server_key(paramiko.RSAKey(filename=_selfKey))
        except Exception:
            print('[W] Could not load host key, generating a new one...')
            _newKey = paramiko.RSAKey.generate(1024)
            protocol.add_server_key(_newKey)
            try:
                _newKey.write_private_key_file(_selfKey)
            except Exception:
                print('[W] Could not write host key, it will change every time.')
    if os.access(Config.SFTP_CMD, os.X_OK):
        protocol.set_subsystem_handler('sftp', SFTPSubsys)

    _server = SSHServer(protocol)
    try:
        protocol.start_server(server=_server)
    except Exception as e:
        if e.__str__():
            print('[D] Server start failed:', e)
        # sock already closed
        protocol.close()
        print('[I] Connection aborted:', addr)
        return

    print('[I] Waiting for login...')
    channel = protocol.accept(Config.LOGIN_TIMEOUT)
    if not channel:
        print('[I] Login aborted')
        # sock already closed
        protocol.close()
        print('[I] Connection closed:', addr)
        return

    _pwd = pwd.getpwnam(_server.username)
    _env = {
        'HOME': _pwd.pw_dir,
        'LS_COLORS': 'no=0',
        'SHELL': _pwd.pw_shell,
    }
    try:
        os.environ.clear()
        os.chdir(_pwd.pw_dir)
        os.setgroups([])
        os.setgid(_pwd.pw_gid)
        os.setuid(_pwd.pw_uid)
    except Exception as e:
        print('[E] Set user failed:', _server.username, e)
        channel.close()
        conn.shutdown(socket.SHUT_RDWR)
        protocol.close()
        print('[I] Connection closed:', addr)
        return

    if not _server.something.wait(10.0):
        print('[W] Timeout waiting for further request')
        channel.close()
        conn.shutdown(socket.SHUT_RDWR)
        protocol.close()
        print('[I] Connection closed:', addr)
        return

    if _server.useShell:
        if _server.client_channel:
            if not _server.usePty:
                channel.sendall(b'You did not (correctly) requested a pty, this is probably not what you want.\r\n')
            try:
                _server.client_channel.invoke_shell()
            except Exception as e:
                print('[D] client_invoke_shell:', e)
                _server.client_channel.close()
                _server.client_sock.shutdown(socket.SHUT_RDWR)
                _server.client_protocol.close()
                channel.sendall(f'Failed to open shell on {_server.trans_server}:{_server.trans_port}: {e}\r\n'.encode())
                channel.close()
                conn.shutdown(socket.SHUT_RDWR)
                protocol.close()
                print('[I] Connection closed:', addr)
                return
            _tIn = threading.Thread(target=handle_input, args=(_server.client_channel, None, channel))
            _tOut = threading.Thread(target=handle_output, args=(_server.client_channel, None, channel))
        else:
            if _server.usePty:
                print('[D] Using pty')
                _env['TERM'] = _server.term[0]
                _shell = subprocess.Popen(
                    [_pwd.pw_shell, '-l'],
                    stdin=_server.pty_slave_fd,
                    stdout=_server.pty_slave_fd,
                    stderr=_server.pty_slave_fd,
                    env=_env,
                    start_new_session=True
                )
                _tIn = threading.Thread(target=handle_input, args=(_shell, _server.pty_master_fd, channel))
                _tOut = threading.Thread(target=handle_output, args=(_shell, _server.pty_master_fd, channel))
            else:
                channel.sendall(b'You did not (correctly) requested a pty, this is probably not what you want.\r\n')
                _shell = subprocess.Popen(
                    [_pwd.pw_shell, '-l'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=_env,
                    start_new_session=True
                )
                _tIn = threading.Thread(target=handle_input, args=(_shell, _shell.stdin.fileno(), channel))
                _tOut = threading.Thread(target=handle_output, args=(_shell, _shell.stdout.fileno(), channel))
        _tIn.start()
        _tOut.start()
        if not _server.client_channel:
            _shell.wait()
            if _server.usePty:
                open(_server.pty_slave_fd, 'wb').write(b'')
        _tIn.join()
        _tOut.join()
    elif _server.useExec:
        if _server.client_channel:
            try:
                _server.client_channel.exec_command(_server.useExec.decode())
            except Exception as e:
                print('[D] client_exec_command:', e)
                _server.client_channel.close()
                _server.client_sock.shutdown(socket.SHUT_RDWR)
                _server.client_protocol.close()
                channel.sendall(f'Failed to execute {_server.useExec.decode()} on {_server.trans_server}:{_server.trans_port}: {e}\r\n'.encode())
                channel.close()
                conn.shutdown(socket.SHUT_RDWR)
                protocol.close()
                print('[I] Connection closed:', addr)
                return
            _tIn = threading.Thread(target=handle_input, args=(_server.client_channel, None, channel))
            _tOut = threading.Thread(target=handle_output, args=(_server.client_channel, None, channel))
        else:
            _args = _server.useExec.split(b' ')
            _exec = subprocess.Popen(
                _args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )
            _tIn = threading.Thread(target=handle_input, args=(_exec, _exec.stdin.fileno(), channel))
            _tOut = threading.Thread(target=handle_output, args=(_exec, _exec.stdout.fileno(), channel))
        _tIn.start()
        _tOut.start()
        if not _server.client_channel:
            _exec.wait()
        _tIn.join()
        _tOut.join()
    elif _server.useSubsystem:
        print('[D] Subsystem:', _server.useSubsystem)
        _server.subSysDone.wait()
    else:
        print('[W] No request received')
        channel.close()

    protocol.close()
    print('[I] Connection closed:', addr)
