FROM rust:latest

RUN apt -y update && apt -y install \
    autoconf-archive \
    libcmocka0 \
    libcmocka-dev \
    procps \
    iproute2 \
    build-essential \
    git \
    pkg-config \
    gcc \
    libtool \
    automake \
    libssl-dev \
    uthash-dev \
    autoconf \
    doxygen \
    libjson-c-dev \
    libini-config-dev \
    libcurl4-openssl-dev \
    uuid-dev \
    libltdl-dev \
    libusb-1.0-0-dev \
    libftdi-dev \
    clang

WORKDIR /build
ADD . /build

# TPM Lib
RUN git clone --depth 1 --branch 4.1.3 https://github.com/tpm2-software/tpm2-tss.git && \
    cd tpm2-tss && \
    ./bootstrap && \
    ./configure --prefix=/usr  && \
    make -j5  && \
    make install