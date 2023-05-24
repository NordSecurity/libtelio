FROM debian:stable-slim as deps-python
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get --quiet --assume-yes --no-install-recommends install \
        python3-pip \
        python3-venv && \
    apt-get clean && \
    python3 -m venv --copies /venv && \
    . /venv/bin/activate && \
    python3 -m pip --no-cache-dir install pynat

FROM debian:stable-slim
LABEL org.opencontainers.image.authors="info@nordsec.com"

COPY --from=deps-python /venv /venv
COPY libtelio/nat-lab/3rd-party/iptables /opt/iptables
COPY libtelio/nat-lab/install_stun_server.sh install_stun_server.sh
COPY libtelio/nat-lab/patches/stun-server/timeval-fix.patch timeval-fix.patch
ENV PATH=/venv/bin:$PATH

# _ALWAYS_ keep these combined, because `apt-get update` caching _will_ bite you
# in the ass one day. Caches are invalidated based on the commands themselves
# in the RUN case and not on the files in the container, so you can get a cache
# hit with an outdated repo information, so, even if you only decide to install
# additional Python packages, we want to ensure that we have the latest packages.
#
# Cleaning the APT cache also reduces image size.
#
# Keeping the package list sorted helps maintain sanity.
RUN \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -qy --no-install-recommends \
        autoconf \
        automake \
        bison \
        build-essential \
        conntrack \
        coturn \
        curl \
        flex \
        iperf3 \
        iproute2 \
        iptables \
        iputils-ping \
        ldnsutils \
        dnsutils \
        libmnl-dev \
        libnftnl-dev \
        libtool \
        miniupnpc \
        net-tools \
        netcat-traditional \
        psmisc \
        python3 \
        stun-client \
        tcpdump \
        watch \
        wget \
        wireguard-tools && \
    apt-get clean

RUN \
case $(uname -m) in \
   aarch64) \
	    wget -qO - http://ftp.de.debian.org/debian/pool/main/g/glibc/multiarch-support_2.28-10+deb10u1_arm64.deb > multiarch-support.deb && \
	    wget -qO - http://launchpadlibrarian.net/350201705/libupnp6_1.6.24-4_arm64.deb > libupnp6.deb && \
	    wget -qO - http://ports.ubuntu.com/pool/universe/l/linux-igd/linux-igd_1.0+cvs20070630-6_arm64.deb > linux-igd.deb ;; \
    x86_64) \
	     wget -qO - http://launchpadlibrarian.net/151925901/multiarch-support_2.17-0ubuntu5.1_amd64.deb > multiarch-support.deb && \
	     wget -qO - http://launchpadlibrarian.net/130170860/libupnp6_1.6.17-1.2_amd64.deb > libupnp6.deb && \
	     wget -qO - http://launchpadlibrarian.net/188321832/linux-igd_1.0+cvs20070630-5_amd64.deb > linux-igd.deb ;; \
esac

RUN \
    dpkg -i multiarch-support.deb && \
    dpkg -i libupnp6.deb && \
    dpkg -i linux-igd.deb && \
    sed -i 's/\/sbin\/iptables/\/usr\/sbin\/iptables/g' /etc/upnpd.conf

RUN \
    ./install_stun_server.sh

RUN \
    cd /opt/iptables && \
    ./autogen.sh && \
    ./configure && \
    make
