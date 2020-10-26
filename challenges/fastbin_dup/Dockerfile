FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home fastbin_dup

COPY .glibc /home/.glibc

WORKDIR /home/fastbin_dup
COPY fastbin_dup .
COPY flag .
RUN chown --recursive root:fastbin_dup /home/fastbin_dup && \
    chmod --recursive 750 /home/fastbin_dup && \
    chmod 740 /home/fastbin_dup/flag

EXPOSE 4444
USER fastbin_dup
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./fastbin_dup",stderr; \
    done
