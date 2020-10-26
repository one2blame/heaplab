FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home unsafe_unlink

COPY .glibc /home/.glibc

WORKDIR /home/unsafe_unlink
COPY unsafe_unlink .
COPY flag .
RUN chown --recursive root:unsafe_unlink /home/unsafe_unlink && \
    chmod --recursive 750 /home/unsafe_unlink && \
    chmod 740 /home/unsafe_unlink/flag

EXPOSE 4444
USER unsafe_unlink
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./unsafe_unlink",stderr; \
    done
