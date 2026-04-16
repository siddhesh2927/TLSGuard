pipeline {
    agent any
    environment {
        IMAGE_NAME = "yourproject-image"
        CONTAINER_NAME = "yourproject-container"
    }
    stages {
        stage('Clone Repository') {
            steps {
                git branch: 'main', url: 'https://github.com/yourusername/your-repo.git'
            }
        }
        stage('Build Docker Image') {
            steps {
                script {
                    sh 'docker build -t $IMAGE_NAME .'
                }
            }
        }
        stage('Stop and Remove Old Container') {
            steps {
                script {
                    sh 'docker rm -f $CONTAINER_NAME || true'
                }
            }
        }
        stage('Run New Container') {
            steps {
                script {
                    sh 'docker run -d --name $CONTAINER_NAME -p 80:80 $IMAGE_NAME'
                }
            }
        }
    }
}
