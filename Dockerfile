FROM ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-pip
RUN pip3 install python-telegram-bot==13.13 python-hostlist==1.21

RUN useradd gentle_scanner -u 10000 -m

WORKDIR /home/gentle_scanner/
