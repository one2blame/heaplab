FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y \
    socat \
&& rm -rf /var/lib/apt/lists/*

RUN useradd -m fastbin_dup

COPY .glibc /home/.glibc

WORKDIR /home/fastbin_dup

COPY fastbin_dup .
COPY flag .
RUN chown -R root:fastbin_dup /home/fastbin_dup && \
    chmod -R 750 /home/fastbin_dup && \
    chmod 740 /home/fastbin_dup/flag

EXPOSE 4444
USER fastbin_dup
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./fastbin_dup",stderr; \
    done
