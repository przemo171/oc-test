stages:
  - deploy
  - package

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=$CI_PROJECT_DIR/.m2/repository"
  OC_SERVER:        "https://api.cluster.example.com:6443"  # → CI variable
  OC_NAMESPACE:     "my-namespace"                           # → CI variable
  BUILDCONFIG_NAME: "maven-test-app"                         # → CI variable
  IMAGE_REGISTRY:   "jfrog.example.com"
  IMAGE_NAME:       "docker-local/maven-test-app"
  RELEASE_REPO:     "local/temp/maven-release-local/pl/example/maven-test-app"

# ── SNAPSHOT ──────────────────────────────────────────────────────────────

deploy_snapshot:
  stage: deploy
  image: jfrog.example.com/local/g-j21-mvn3915jfrog:latest
  script:
    - mkdir -p ~/.m2
    - cp ci-settings.xml ~/.m2/settings.xml
    - mvn clean deploy -DskipTests
    - mvn help:evaluate -Dexpression=project.version -q -DforceStdout > .version
  artifacts:
    paths:
      - target/maven-test-app-*.jar
      - .version
    expire_in: 1 hour
  only:
    - main
  tags:
    - test

build_image_snapshot:
  stage: package
  image: jfrog.example.com/local/g-j21-mvn3915jfrog:latest
  needs:
    - job: deploy_snapshot
      artifacts: true
  script:
    - VERSION=$(cat .version)
    - .ci/oc-login.sh
    - oc patch bc/$BUILDCONFIG_NAME -n $OC_NAMESPACE
        -p "{\"spec\":{\"output\":{\"to\":{\"name\":\"${IMAGE_REGISTRY}/${IMAGE_NAME}:${VERSION}\"}}}}"
    - oc start-build $BUILDCONFIG_NAME -n $OC_NAMESPACE --from-dir=. --wait
  only:
    - main
  tags:
    - test

# ── RELEASE ───────────────────────────────────────────────────────────────

release:
  stage: deploy
  image: jfrog.example.com/local/g-j21-mvn3915jfrog:latest
  script:
    - git config --global user.email "mail@example.com"
    - git config --global user.name "GitLab CI (robot)"
    - git remote set-url origin https://gitlab-ci-token:${GITLAB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git
    - git checkout -B "$CI_COMMIT_REF_NAME"
    - git reset --hard origin/$CI_COMMIT_REF_NAME
    - git clean -fd
    - mkdir -p ~/.m2
    - cp ci-settings.xml ~/.m2/settings.xml
    - rm -f release.properties pom.xml.releaseBackup pom.xml.tag pom.xml.next pom.xml.backup
    - mvn -B -e release:clean release:prepare release:perform -DskipTests -DscmCommentPrefix="[ci skip] "
  when: manual
  only:
    - main
  tags:
    - test

build_image_release:
  stage: package
  image: jfrog.example.com/local/g-j21-mvn3915jfrog:latest
  needs:
    - job: release
  script:
    - git fetch --tags
    - VERSION=$(git describe --tags --abbrev=0 | sed 's/^v//')
    - mkdir -p target
    - curl -f -u "$ARTIFACTORY_USER:$ARTIFACTORY_PASS"
        "https://${IMAGE_REGISTRY}/artifactory/${RELEASE_REPO}/${VERSION}/maven-test-app-${VERSION}.jar"
        -o "target/maven-test-app-${VERSION}.jar"
    - .ci/oc-login.sh
    - oc patch bc/$BUILDCONFIG_NAME -n $OC_NAMESPACE
        -p "{\"spec\":{\"output\":{\"to\":{\"name\":\"${IMAGE_REGISTRY}/${IMAGE_NAME}:${VERSION}\"}}}}"
    - oc start-build $BUILDCONFIG_NAME -n $OC_NAMESPACE --from-dir=. --wait
    # dodatkowo tag latest
    - oc patch bc/$BUILDCONFIG_NAME -n $OC_NAMESPACE
        -p "{\"spec\":{\"output\":{\"to\":{\"name\":\"${IMAGE_REGISTRY}/${IMAGE_NAME}:latest\"}}}}"
    - oc start-build $BUILDCONFIG_NAME -n $OC_NAMESPACE --from-dir=. --wait
  when: manual
  only:
    - main
  tags:
    - test
