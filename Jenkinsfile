pipeline {
    agent any

    // We reference the NodeJS tool. 
    // IMPORTANT: Make sure this is set to NodeJS 20.x or 18.x in Jenkins to avoid the libatomic crash!

    tools {
        nodejs 'NodeJs'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out code from Repository..."
                checkout scm
            }
        }


        stage('Install Dependencies') {
            steps {
                echo "Installing NPM Workspaces Dependencies..."
                sh 'npm cache clean --force'
                sh 'npm install'
            }
        }

        stage('Verify Type Safety') {
            steps {
                echo "Verifying Backend TypeScript Types..."
                dir('server') {
                    sh 'npx tsc --noEmit'
                }
            }
        }

        stage('Build Frontend App') {
            steps {
                echo "Testing React Build..."
                dir('client') {
                    sh 'npm run build'
                }
            }
        }

        stage('Deploy with Docker Compose') {
            steps {
                echo "Cleaning up previous application containers..."
                sh 'docker rm -f tlsguard-frontend tlsguard-backend || true'
                echo "Deploying Live Application via Docker Compose..."
                sh 'docker-compose up -d --build frontend backend'
            }
        }

    }

    post {
        always {
            // Clean up the workspace to save disk space on Jenkins
            cleanWs()
            echo "CI/CD Pipeline Finished!"
        }
        success {
            echo "Build was successful! ✅ Your code is verified and safe."
        }
        failure {
            echo "Build failed! ❌ Check the Jenkins logs."
        }
    }
}