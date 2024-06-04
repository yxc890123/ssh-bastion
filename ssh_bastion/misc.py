import os, re, ctypes


def set_cgroup(pid):
    _cgroup_base_dirs = []
    for line in open('/proc/mounts').readlines():
        if ' cgroup' in line:
            for _o in line.split(' ')[3].split(','):
                if _o == 'rw':
                    _cgroup_base_dirs.append((line.split(' ')[1], line.split(' ')[2]))
                    break
                elif _o == 'ro':
                    break

    if len(_cgroup_base_dirs) == 0:
        print('[W] Cgroup not vailable.')
        return

    _cgroup_paths = []
    for line in open('/proc/self/cgroup').readlines():
        if '.slice' in line:
            _subsys = line.split(':')[1].strip()
            _cgroup_path = re.sub(r'^/?(.*?\.slice).*', r'\1', line.split(':')[2].strip())
            for _base_dir, _version in _cgroup_base_dirs:
                if _version == 'cgroup':
                    _pid_file = 'tasks'
                elif _version == 'cgroup2':
                    _pid_file = 'cgroup.procs'
                else:
                    print('[W] Unknown cgroup version:', _version)
                    continue

                if _subsys in _base_dir or _base_dir.split('/')[-1] in _subsys:
                    if _subsys == 'devices':
                        _cgroup_paths.append((f'{_base_dir}/{_cgroup_path}', _pid_file))
                    else:
                        _cgroup_paths.append((f'{_base_dir}/{_cgroup_path}/ssh-proxy/{pid}', _pid_file))
                    break

    for _cgroup_dir, _pid_file in _cgroup_paths:
        try:
            os.makedirs(_cgroup_dir, 0o755, True)
            open(f'{_cgroup_dir}/{_pid_file}', 'a').write(f'{pid}\n')
            print('[D] set cgroup in:', _cgroup_dir)
        except Exception as e:
            print('[W] Set cgroup failed:', e)


def set_cmdline(name):
    # make ps command result fancy
    _libc = ctypes.CDLL(ctypes.util.find_library('c'))
    # set /proc/self/cmdline
    try:
        _cmdline_p = ctypes.c_char_p.in_dll(_libc, '__progname_full')
        _cmdline_f = open('/proc/self/cmdline', 'rb').read1()
    except Exception as e:
        print('[W] Failed to get process cmdline:', e)

    try:
        # strcpy: copy arg1 to arg0, returns a pointer of arg0
        # only do this without padding will leave long cmdline uncut
        # and strcpy can't pad \0
        _rt = _libc.strcpy(_cmdline_p, name.encode() + b' ' * (len(_cmdline_f) - len(name)))
        if _rt == 0:
            print('[W] Failed to set cmdline:', _rt)
            return
        # only do this will cause weird result like put environ strings into cmdline, overflow?
        _rt = _libc.strncpy(_cmdline_p, name.encode(), max(len(_cmdline_f), len(name)))
        if _rt == 0:
            print('[W] Failed to set cmdline:', _rt)
            return
    except Exception as e:
        print('[W] Failed to set cmdline:', e)
