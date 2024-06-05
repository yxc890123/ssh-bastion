#!/usr/bin/env python3

import sys, os
import inspect
import signal
import socket
import multiprocessing, threading
import ctypes
from getopt import getopt

# from core: raise "No module named 'core'" if run from package entrypoint
# from .core: raise "attempted relative import with no known parent package" if run from cli.py
# from ssh_bastion.core: raise "No module named 'ssh_bastion'" if run from cli.py without installing package
# so, do this:
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ssh_bastion.core import handle_connection
from ssh_bastion.config import COMMON_NAME, CONF_FILE, Config
from ssh_bastion.misc import set_cmdline

Config = Config()

entry_file = inspect.stack()[-1].filename
unit_file = f'/usr/local/lib/systemd/system/{COMMON_NAME}.service'
help_text = f'''{COMMON_NAME}

SSH proxy server.
Version: 0.0

Usage:
    {entry_file} -s [-c FILE]
    {entry_file} -i [-c FILE]
    {entry_file} -g [-c FILE]
    {entry_file} -p [-c FILE]

Options:
    -h, --help              Show this message.

    -s, --start             Start server.
    -i, --install-unit      Set/reset systemd unit.
                            Located at {unit_file}.
    -u, --uninstall-unit    Unset systemd unit.
    -g, --generate-config   Generate config file with default settings.
                            (Not implemented yet.)
    -p, --parse-config      Show parsed settings.
                            (Not implemented yet.)

    -c, --config-file FILE  Specify the path of config FILE along with options above.
                            Default is {CONF_FILE}.
                            (Not implemented yet.)
'''
_conf_file = None


def usage():
    print(help_text)


def start_server():
    if os.getuid() != 0:
        print('[E] Must run as root.')
        return False

    try:
        _sock = socket.create_server(('', Config.SSH_PORT), family=socket.AF_INET6, backlog=128, reuse_port=True, dualstack_ipv6=True)
        _sockname = _sock.getsockname()
        print('[I] Listening on', _sockname)
    except Exception as e:
        print('[E] Socket creation failed:', e)
        return False
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

    _libc = ctypes.CDLL(ctypes.util.find_library('c'))
    # set /proc/self/comm, once
    try:
        _rt = _libc.prctl(15, COMMON_NAME.encode(), 0, 0, 0)
        if _rt != 0:
            print('[W] Failed to set process name:', _rt)
    except Exception as e:
        print('[W] Failed to set process name:', e)

    set_cmdline(f'{COMMON_NAME} [listener]: {_sockname[0]}:{_sockname[1]}')

    while True:
        conn, addr = _sock.accept()
        _sessions = len(multiprocessing.active_children())
        print('[D] Active sessions:', _sessions)
        if _sessions >= Config.MAX_SESSIONS:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            print('[W] Too many sessions, rejecting:', addr)
            continue
        print('[I] Connection accepted:', addr)
        _child = multiprocessing.Process(target=handle_connection, args=(conn, addr))
        _child.start()
        threading.Thread(target=lambda ps: ps.join(), args=(_child,)).start()


def install_unit():
    if os.system('systemctl status >/dev/null 2>&1') == 0:
        _text = f'''[Unit]
After=network.target

[Service]
Environment=PYTHONUNBUFFERED=1
ExecStart={sys.executable} {entry_file} -s{f' -c {_conf_file}' if _conf_file else ''}
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
'''
        try:
            os.makedirs(os.path.dirname(unit_file), 0o755, True)
            open(unit_file, 'w').write(_text)
        except Exception as e:
            print('[E] Failed to write unit file:', e)
            return False

        os.system('systemctl daemon-reload')
        print('[I] Systemd unit set:', unit_file)
    else:
        print('[W] Systemd is not ready.')
        return False


def uninstall_unit():
    if os.system('systemctl status >/dev/null 2>&1') == 0:
        try:
            os.remove(unit_file)
        except Exception:
            pass
        os.system('systemctl daemon-reload')
        print('[I] Systemd unit deleted.')
    else:
        print('[W] Systemd is not ready.')
        return False


def gen_conf():
    # TODO
    pass


def parse_conf():
    # TODO
    pass


def main():
    signal.signal(signal.SIGHUP, Config.reload)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)

    try:
        (opts, args) = getopt(
            sys.argv[1:],
            'hsiugpc:',
            [
                'help',
                'start',
                'install-unit',
                'uninstall-unit',
                'generate-config',
                'parse-config',
                'config-file='
            ]
        )
        # print('[D] command line args:', opts, args)
    except Exception as e:
        print('[E] Invalid arguments:', e, end='\n\n')
        usage()
        exit(1)
    if len(opts) == 0:
        print('[E] Arguments required.', end='\n\n')
        usage()
        exit(1)
    if len(args) > 0:
        print('[E] Invalid arguments:', args[0], end='\n\n')
        usage()
        exit(1)

    action = None
    global _conf_file
    for opt in opts:
        if opt[0] in ('-s', '--start'):
            if not action:
                action = start_server
        elif opt[0] in ('-i', '--install-unit'):
            if not action:
                action = install_unit
        elif opt[0] in ('-u', '--uninstall-unit'):
            if not action:
                action = uninstall_unit
        elif opt[0] in ('-g', '--generate-config'):
            if not action:
                action = gen_conf
        elif opt[0] in ('-p', '--parse-config'):
            if not action:
                action = parse_conf
        elif opt[0] in ('-c', '--config-file'):
            _conf_file = opt[1]
        elif opt[0] in ('-h', '--help'):
            action = usage

    if not action:
        print('[E] Invalid arguments.', end='\n\n')
        usage()
        exit(1)

    Config.load(_conf_file)
    result = action()
    if result is not None:
        exit(1)


if __name__ == '__main__':
    main()
