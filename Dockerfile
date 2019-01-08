# PcapXray Project Dockerfile - https://github.com/Srinivas11789/PcapXray

# Latest ubuntu base image
FROM ubuntu:latest

# Maintainer
MAINTAINER Srinivas Piskala Ganesh Babu "spg349@nyu.edu"

# Apt update and install - nginx and git
RUN apt-get update
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y graphviz
RUN apt-get install -y python-tk
RUN apt-get install -y python-pip
RUN apt-get install -y nginx
RUN apt-get install -y git-core
RUN apt-get install -y sudo
RUN apt-get install -y libx11-dev

# Fetching the latest source code from the github repo of devOps
RUN git clone https://github.com/srinivas11789/PcapXray
RUN pip install -r PcapXray/requirements.txt

WORKDIR PcapXray/Source
CMD python main.py
