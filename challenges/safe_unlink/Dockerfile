FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home safe_unlink

COPY .glibc /home/.glibc

WORKDIR /home/safe_unlink
COPY safe_unlink .
COPY flag .
RUN chown --recursive root:safe_unlink /home/safe_unlink && \
    chmod --recursive 750 /home/safe_unlink && \
    chmod 740 /home/safe_unlink/flag

EXPOSE 4444
USER safe_unlink
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./safe_unlink",stderr; \
    done
