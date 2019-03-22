pipeline {
  agent any
  stages {
    stage('Deploy Build to ESX') {
      parallel {
        stage('Deploy Build to ESX') {
          steps {
            sh '''echo \'Deploying ESX\'
sh \'python part1/deploy_esx.py\''''
          }
        }
        stage('Deploy VCSA') {
          steps {
            sh '''echo \'Deploying VCSA\'
sh \'python part1/deploy_vcsa.py\''''
          }
        }
      }
    }
  }
}