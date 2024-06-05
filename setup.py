from setuptools import setup
import sys

if sys.platform != 'linux':
    raise OSError('This package can only be installed on Linux system.')

setup(
    name='ssh_bastion',
    version='0.0.3',
    description='SSH proxy server.',
    long_description=open('./README.md').read(),
    long_description_content_type='text/markdown',
    author='yxc890123',
    url='https://github.com/yxc890123/ssh-bastion',
    packages=['ssh_bastion'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3'
    ],
    license='Apache 2.0',
    include_package_data=True,
    python_requires='>=3.6',
    install_requires=[
        'paramiko',
        'python-pam',
        'six'
    ],
    entry_points={
        'console_scripts': ['ssh-bastion = ssh_bastion.cli:main']
    }
)
