pipeline {
    agent {
        label 'nix'
    }
    stages {
        stage('Test') {
            steps {
                sh "/home/jenkins/.nix-profile/bin/nix-build default.nix"
		echo env.PWD
		sh "ls -l result/"
                junit 'result/test-results.xml'
            }
        }
    }
}
