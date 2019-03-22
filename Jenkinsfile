pipeline {
  agent any
  stages {
    parameters {
    booleanParam(
    name:"AAA",
    defaultValue:true,
    description: "CheckBox parameter")
    String(
    name:"BBBB",
    defaultValue:"Need a Path",
    description: "Want to dance")
    }
    stage('Example') {
      echo "Hello world"
      echo "Diff Hello world"
      echo "trying ${params.AAA}"
        }
        
  }
}
