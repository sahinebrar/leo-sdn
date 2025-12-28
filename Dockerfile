FROM ubuntu:20.04

# Etkileşimsiz kurulum
ENV DEBIAN_FRONTEND=noninteractive

# Temel araçları kur
RUN apt-get update && apt-get install -y \
    sudo \
    lsb-release \
    openvswitch-switch \
    python3-pip \
    python3-dev \
    iputils-ping \
    iproute2 \
    net-tools \
    hping3 \
    tcpdump \
    vim \
    nano \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    iperf \
    iperf3 \
    curl \
    psmisc \
    cgroup-tools \
    help2man \
    pyflakes3 \
    pylint \
    pep8

# Mininet'i kaynaktan tam kur (apt cache temizlemeden önce)
RUN git clone https://github.com/mininet/mininet.git /opt/mininet && \
    cd /opt/mininet && \
    PYTHON=python3 util/install.sh -nfv && \
    pip3 install .

# Apt cache temizle
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Pip'i güncelle, setuptools'u eski versiyona pin'le
RUN pip3 install --upgrade pip && \
    pip3 install setuptools==58.2.0 wheel

# Ryu ve bağımlılıklarını kur
RUN pip3 install \
    ryu \
    eventlet==0.30.2 \
    oslo.config \
    ovs \
    msgpack \
    netaddr \
    tinyrpc

# ML ve analiz kütüphaneleri
RUN pip3 install \
    scikit-learn \
    numpy \
    pandas \
    networkx \
    matplotlib \
    pyyaml \
    joblib

# Entrypoint scriptini kopyala
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Proje dosyalarını kopyala
COPY . /root/leo-sdn-attack
WORKDIR /root/leo-sdn-attack

# Ryu SDN Controller portları
EXPOSE 6633 6653 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
