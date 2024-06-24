# ssh-bastion

SSH proxy server.

Transport ssh connection to other servers.

Based on [paramiko](https://github.com/paramiko/paramiko)👍.

## Why

System managers may want to limit access routes to their servers,
so this tool can act as a bastion or proxy or whatever-you-call server.

And also if you want the activities of what users did on these servers,
the logging function could help.

## What can do

1. Just works as a normal ssh server.
2. Connect to other ssh servers through this tool.

## What can not do

1. GSSAPI(Kerberos) authentication: Nah...
2. Port, X11 or any other forwarding: Not the purpose of this project.

## Requirements

- Python: 3.6+
  - [paramiko](https://pypi.org/project/paramiko/)
  - [python-pam](https://pypi.org/project/python-pam/)
  - [six](https://pypi.org/project/six/) (Needed by python-pam😟)
- OS: Linux
  - PAM module
  - Shell
  - OpenSSH-client (for scp)
  - OpenSSH-server (for sftp)

## Installation

```bash
pip install ssh-bastion
```

## Usage

To start the server:

```bash
ssh-bastion -s
```

For more information:

```bash
ssh-bastion -h
```

Login

1. As a normal ssh server, you know how to use it.
2. As a proxy server:
   - Use username like this: `<username of proxy>#<username of target>@<hostname or IP of target>[:<port of target>]`
     - You need to use "%" to escape "#", "@", "%" in both usernames.

        For example: `A%@very%#strange%%username#%#another%%strange%username@192.168.1.100:2222`

        This will connect to `192.168.1.100:2222` with user `#another%strangeusername` via user `A@very#strange%username` on proxy server.
   - Use password like this: `<password of proxy>#<password of target>`
     - Same as username, you need to use "%" to escape "#" in both passwords.
   - When use private key authentication, put the key in ~/.ssh, and name it like this: `<username of target>@<hostname or IP of target>[:<port of target>]`
     - Use "%" to escape "@" in username.

## Still working on😴

1. Make command line tool.
   1. ~~Start the server.~~
   2. ~~Set/unset systemd unit file. (Including reload)~~
   3. Generate default config file.
   4. Show parsed configuration.
2. ~~PyPI packaglize.~~
3. Private key authentication.
4. Logging.
   1. System log
      1. DEBUG
      2. INFO
      3. WARNING
      4. ERROR
      5. CRITICAL
      6. OFF
   2. Access log
      1. DUMP (file)
      2. INFO
      3. OFF
   3. File (transfer) log
      1. DUMP (file)
      2. INFO
      3. OFF
5. Configuration file. (Including accesss control)

## Vulnerabilities😴

Not yet, will check after all features are done.

## Disclaimer

Use at your own risk.
