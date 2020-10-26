FROM ubuntu:18.04

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update --yes && apt-get install --yes \
    socat \
&& rm --recursive --force /var/lib/apt/lists

RUN useradd --create-home house_of_force

COPY .glibc /home/.glibc

WORKDIR /home/house_of_force
COPY house_of_force .
COPY flag .
RUN chown --recursive root:house_of_force /home/house_of_force && \
    chmod --recursive 750 /home/house_of_force && \
    chmod 740 /home/house_of_force/flag

EXPOSE 4444
USER house_of_force
CMD while true; do \
        socat TCP-LISTEN:4444,reuseaddr,fork EXEC:"./house_of_force",stderr; \
    done
