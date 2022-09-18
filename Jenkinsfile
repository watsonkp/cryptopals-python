pipeline {
    agent {
        label 'nix'
    }
    stages {
        stage('Test') {
            steps {
                sh '/home/jenkins/.nix-profile/bin/nix-build cryptowrapper/develop.nix -o cryptowrapper/result'
                sh 'cp --remove-destination cryptowrapper/result/lib/libcryptowrapper-0.1.0.so .'
                sh '/home/jenkins/.nix-profile/bin/nix-build gmpwrapper/develop.nix -o gmpwrapper/result'
                sh 'cp --remove-destination gmpwrapper/result/lib/libgmpwrapper-0.1.0.so .'
                sh "/home/jenkins/.nix-profile/bin/nix-shell --command 'pytest --junitxml=test-results.xml' develop.nix"
                junit 'test-results.xml'
            }
        }
    }
}
