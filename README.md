# esxi_6.7_info

-- Need https://github.com/vmware/pyvmomi/tree/master/pyVim
-- Need Python3.8. Install python3.8 for debian 10 (example)
```

apt-get install -y build-essential checkinstall libreadline-gplv2-dev libncursesw5-dev libssl-dev \
libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev zlib1g-dev openssl libffi-dev python3-dev python3-setuptools wget
apt-get install liblzma-dev
apt-get install zlib1g-dev

mkdir -p /tmp/Python38 && cd /tmp/Python38 && \
wget https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tar.xz && \
tar xf Python-3.8.2.tar.xz && cd Python-3.8.2

./configure --enable-optimizations
make altinstall -j
```

python3.8 demo.py
