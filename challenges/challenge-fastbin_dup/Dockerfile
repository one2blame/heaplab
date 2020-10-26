FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home fastbin_dup_2

COPY .glibc /home/.glibc

WORKDIR /home/fastbin_dup_2
COPY fastbin_dup_2 .
COPY flag .
RUN chown --recursive root:fastbin_dup_2 /home/fastbin_dup_2 && \
    chmod --recursive 750 /home/fastbin_dup_2 && \
    chmod 740 /home/fastbin_dup_2/flag

EXPOSE 4444
USER fastbin_dup_2
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./fastbin_dup_2",stderr; \
    done
