FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home house_of_spirit

COPY .glibc /home/.glibc

WORKDIR /home/house_of_spirit
COPY house_of_spirit .
RUN chown --recursive root:house_of_spirit /home/house_of_spirit && \
    chmod --recursive 750 /home/house_of_spirit

EXPOSE 4444
USER house_of_spirit
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./house_of_spirit",stderr; \
    done
