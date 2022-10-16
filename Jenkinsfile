pipeline {
    agent {
        label 'nix'
    }
    stages {
        stage('Test') {
            steps {
                sh "/home/jenkins/.nix-profile/bin/nix-build default.nix"
                junit 'result/test-results.xml'
            }
        }
    }
}
