# Imagen Base
FROM centos:centos7

# Version de Maven y Java que se instalara
ENV JAVA_VERSON 1.8.0
ENV MAVEN_VERSION 3.3.9

# Creamos usuarios para el docker
USER root

# Copiamos todo el repo a la carpeta source
RUN mkdir /source
COPY . /source

# Instalamos Java 8
RUN yum update -y && \
  yum install -y curl && \
  yum install -y java-$JAVA_VERSON-openjdk java-$JAVA_VERSON-openjdk-devel && \
  yum clean all

# Instalamos Maven
RUN curl -fsSL https://archive.apache.org/dist/maven/maven-3/$MAVEN_VERSION/binaries/apache-maven-$MAVEN_VERSION-bin.tar.gz | tar xzf - -C /usr/share \
  && mv /usr/share/apache-maven-$MAVEN_VERSION /usr/share/maven \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

# Generamos las variables de entorno de Maven y Java
ENV JAVA_HOME /usr/lib/jvm/java
ENV M2_HOME /usr/share/maven
ENV maven.home $M2_HOME
ENV M2 $M2_HOME/bin
ENV PATH $M2:$PATH

#Compilamos con maven y copiamos el jar generado en la carpeta tmp
WORKDIR /source
RUN mvn clean install
RUN cp ./target/calculator-0.0.1.jar /tmp/

# Cambio ruta
WORKDIR /tmp

# Creamos un usuario sin home, le damos permisos al jar a este usuario y cambiamos a este
RUN useradd --no-create-home --shell /bin/sh nonroot
RUN chown nonroot calculator-0.0.1.jar
USER nonroot
