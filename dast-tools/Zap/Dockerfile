#Imagen Base
FROM centos:centos7

#Datos de entrada
ARG VERSION=2.0.0

#Creamos usuarios para el docker
USER root

#Instalamos Java 8
RUN yum update -y && \
yum install -y wget && \
yum install -y java-1.8.0-openjdk java-1.8.0-openjdk-devel && \
yum clean all

#Cambio ruta
WORKDIR /tmp

#Creamos un usuario sin home y cambiamos a este
RUN useradd --no-create-home --shell /bin/sh nonroot
USER nonroot
