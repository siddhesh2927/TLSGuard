# Jenkins Dockerfile
FROM jenkins/jenkins:lts
USER root
# Install Docker CLI (optional, for Docker-in-Docker builds)
RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*
# Allow Jenkins user to use Docker
RUN usermod -aG docker jenkins
USER jenkins
