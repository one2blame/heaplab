FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home one_byte

COPY .glibc /home/.glibc

WORKDIR /home/one_byte
COPY one_byte .
COPY flag .
RUN chown --recursive root:one_byte /home/one_byte && \
    chmod --recursive 750 /home/one_byte && \
    chmod 740 /home/one_byte/flag

EXPOSE 4444
USER one_byte
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./one_byte",stderr; \
    done
