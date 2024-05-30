import signal, os
import socket
import multiprocessing, threading
import ctypes
import config

from core import set_cmdline, handle_connection


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)

    if os.getuid() != 0:
        print('[E] Must run as root.')
        exit(1)

    try:
        _sock = socket.create_server(('', config.SSH_PORT), family=socket.AF_INET6, backlog=128, reuse_port=True, dualstack_ipv6=True)
    except Exception as e:
        print('[E] Socket creation failed:', e)
        exit(1)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

    _libc = ctypes.CDLL(ctypes.util.find_library('c'))
    # set /proc/self/comm, once
    try:
        _rt = _libc.prctl(15, b'ssh-proxy', 0, 0, 0)
        if _rt != 0:
            print('[W] Failed to set process name:', _rt)
    except Exception as e:
        print('[W] Failed to set process name:', e)

    set_cmdline(f'ssh-proxy [listener]: {_sock.getsockname()[0]}:{config.SSH_PORT}')

    while True:
        conn, addr = _sock.accept()
        _sessions = len(multiprocessing.active_children())
        print('[D] Active sessions:', _sessions)
        if _sessions >= config.MAX_SESSIONS:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            print('[W] Too many sessions, rejecting:', addr)
            continue
        print('[I] Connection accepted:', addr)
        _child = multiprocessing.Process(target=handle_connection, args=(conn, addr))
        _child.start()
        threading.Thread(target=lambda ps: ps.join(), args=(_child,)).start()
