# PcapXray Project Dockerfile - https://github.com/Srinivas11789/PcapXray

# Latest ubuntu base image
FROM ubuntu:latest

# Maintainer
MAINTAINER Srinivas Piskala Ganesh Babu "spg349@nyu.edu"

# Apt update and install - nginx and git
#RUN apt-get update && apt-get upgrade -y
RUN apt-get update
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y graphviz
RUN apt-get install -y python3-tk
RUN apt-get install -y python3-pip
RUN apt-get install -y python3-pil 
RUN apt-get install -y python3-pil.imagetk
RUN apt-get install -y nginx
RUN apt-get install -y git-core
RUN apt-get install -y sudo
RUN apt-get install -y libx11-dev
RUN apt-get install -y libnss3
RUN apt-get install -y libx11-xcb1
RUN apt-get update && \ 
     apt-get install -yq --no-install-recommends \ 
     libasound2 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 \ 
     libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 \ 
     libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 \ 
     libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \ 
     libnss3 
RUN apt-get install -y libgtk2.0-0

# Fetching the latest source code from the github repo of pcapxray
RUN git clone https://github.com/srinivas11789/PcapXray

### Master branch changes - srinivas11789/pcapxray
RUN pip3 install --upgrade -r PcapXray/requirements.txt

WORKDIR PcapXray/Source
CMD python3 main.py

### Develop/Beta branch changes - srinivas11789/pcapxray-beta
#WORKDIR PcapXray
#RUN git checkout develop
#RUN pip install -r requirements.txt
#WORKDIR Source
#CMD python main.py

