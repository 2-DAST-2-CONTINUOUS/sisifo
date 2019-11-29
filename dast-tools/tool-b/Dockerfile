#Imagen Base
FROM ubuntu:latest

#Creamos usuarios para el docker
USER root

# Install required dependencies
RUN apt update
RUN apt-get install build-essential curl libcurl4 libcurl4-openssl-dev ruby ruby-dev wget -y

WORKDIR /tmp

#Download Arachni
RUN wget "https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz" -O /tmp/arachni.tar.gz
RUN mkdir /arachni

WORKDIR /arachni

#Unpack Arachni
RUN tar -xzf /tmp/arachni.tar.gz --strip-components=1 -C /arachni && rm /tmp/arachni.tar.gz

WORKDIR /arachni/bin

RUN chmod +x ./arachni && chmod +x ./arachni_reporter

#Creation of nonroot user
RUN useradd --no-create-home --shell /bin/sh arachni
USER arachni
