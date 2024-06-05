import os

COMMON_NAME = 'ssh-bastion'
CONF_FILE = f'{os.path.dirname(os.path.abspath(__file__))}/{COMMON_NAME}.conf'


class Config(object):
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self.PATH = None
            self.LOGIN_RETRY = 3
            self.LOGIN_TIMEOUT = 60.0
            self.SSH_PORT = 3000
            self.RSA_KEY = 'ssh_host_rsa_key'
            self.SFTP_CMD = '/usr/libexec/openssh/sftp-server'
            self.MAX_SESSIONS = 10

            self._initialized = True

    def load(self, path):
        if path is None:
            if os.access(CONF_FILE, os.R_OK):
                print('[I] Loading config:', CONF_FILE)
                open(CONF_FILE)
        else:
            self.PATH = path
            try:
                print('[I] Loading config:', path)
                open(path)
            except Exception as e:
                print('[W] Failed to open config file:', e)
                print('[W] Start with default settings.')
                return

        # TODO: load config from file
        pass

    def reload(self, *_):
        if self.PATH is None:
            if os.access(CONF_FILE, os.R_OK):
                print('[I] Reloading config:', CONF_FILE)
                open(CONF_FILE)
            else:
                print('[I] No config file specified, nothing happened.')
        else:
            try:
                print('[I] Reloading config:', self.PATH)
                open(self.PATH)
            except Exception as e:
                print('[W] Failed to open config file:', e)
                print('[W] Nothing happened.')
                return

        # TODO: load config from file
        pass
