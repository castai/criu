FROM ubuntu:24.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
	libnet-dev \
	libnl-route-3-dev \
	gcc \
	bsdmainutils \
	build-essential \
	git-core \
	iptables \
	libaio-dev \
	libbsd-dev \
	libcap-dev \
	libnl-3-dev \
	libprotobuf-c-dev \
	libprotobuf-dev \
	libselinux-dev \
	libpcre2-dev \
	iproute2 \
	kmod \
	pkg-config \
	protobuf-c-compiler \
	protobuf-compiler \
	python3-minimal \
	python3-protobuf \
	uuid-dev \
	python3-yaml

COPY . /criu
WORKDIR /criu
RUN make mrproper && make -j $(nproc)

ENTRYPOINT ["./test/zdtm.py"]
