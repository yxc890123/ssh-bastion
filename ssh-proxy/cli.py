import signal, os
import socket
import multiprocessing, threading
import ctypes
import sys
from getopt import getopt

from core import set_cmdline, handle_connection
import config

Config = config.Config()

script_file = os.path.basename(__file__)
unit_file = '/usr/local/lib/systemd/system/ssh-proxy.service'
help_text = f'''ssh-proxy

Transport ssh connection to other servers.
Version: 0.0

Usage:
    {script_file} -s [-c FILE]
    {script_file} -i [-c FILE]
    {script_file} -g [-c FILE]
    {script_file} -p [-c FILE]

Options:
    -h, --help              Show this message.

    -s, --start             Start server.
    -i, --install-unit      Set/reset systemd unit.
                            At {unit_file}
    -u, --uninstall-unit    Unset systemd unit.
    -g, --generate-config   Generate config file with default setting.
                            Not implemented yet.
    -p, --parse-config      Show parsed setting.
                            Not implemented yet.

    -c, --config-file FILE  Specify the path of config file,
                            default is {config.conf_file}.
                            Not implemented yet.
'''


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
        _rt = _libc.prctl(15, b'ssh-proxy', 0, 0, 0)
        if _rt != 0:
            print('[W] Failed to set process name:', _rt)
    except Exception as e:
        print('[W] Failed to set process name:', e)

    set_cmdline(f'ssh-proxy [listener]: {_sockname[0]}:{_sockname[1]}')

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
ExecStart={sys.executable} {__file__} -s{f' -c {conf_file}' if conf_file else ''}
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

    global conf_file

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
            conf_file = opt[1]
        elif opt[0] in ('-h', '--help'):
            action = usage

    Config.load(conf_file)
    result = action()
    if result is not None:
        exit(1)


conf_file = None

if __name__ == '__main__':
    main()
