FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
    strace \
    file \
    gdb

RUN useradd --create-home malloc_testbed

COPY .glibc /home/.glibc
COPY .links /home/malloc_testbed/.links

WORKDIR /home/malloc_testbed
COPY malloc_testbed .
COPY flag .
RUN chown --recursive root:malloc_testbed /home/malloc_testbed && \
    chmod --recursive 750 /home/malloc_testbed && \
    chmod 740 /home/malloc_testbed/flag

EXPOSE 4444
USER malloc_testbed
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./malloc_testbed",stderr; \
    done
