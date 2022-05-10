FROM fedora:34
RUN dnf makecache && \
  dnf groupinstall "Development Tools" -y && \
  dnf install bash unzip vim curl wget -y && \
  dnf install meson python3-pyelftools python3-pip numactl-devel libbpf-devel libpcap-devel openssl-devel -y && \
  pip3 install ninja && \
  dnf clean all

FROM rockylinux:8
RUN dnf makecache && \
  dnf groupinstall "Development Tools" -y && \
  dnf install bash unzip vim curl wget -y && \
  dnf install epel-release -y && \
  dnf install --enablerepo=powertools meson python3-pyelftools python3-pip numactl-devel libbpf-devel libpcap-devel openssl-devel -y && \
  pip3 install ninja && \
  dnf clean all
