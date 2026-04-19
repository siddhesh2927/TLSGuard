FROM jenkins/jenkins:lts

USER root

# 1. Download the Docker CLI safely (bypassing Linux apt-get)
RUN curl -fsSL -o docker.tgz "https://download.docker.com/linux/static/stable/x86_64/docker-26.0.0.tgz" && \
    tar -xzf docker.tgz && \
    mv docker/docker /usr/local/bin/docker && \
    rm -rf docker docker.tgz

# 2. Download Docker Compose statically
RUN curl -fsSL -o /usr/local/bin/docker-compose "https://github.com/docker/compose/releases/download/v2.26.1/docker-compose-linux-x86_64" && \
    chmod +x /usr/local/bin/docker-compose

USER jenkins
