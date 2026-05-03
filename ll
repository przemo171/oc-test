[INFO] [INFO] Installing /builds/group/user/test/target/checkout/pom.xml to /builds/group/user/test/.m2/repository/pl/example/maven-test-app/1.0/maven-test-app-1.0.pom
[INFO] [INFO] Installing /builds/group/user/test/target/checkout/target/maven-test-app-1.0.jar to /builds/group/user/test/.m2/repository/pl/example/maven-test-app/1.0/maven-test-app-1.0.jar
[INFO] [INFO] 
[INFO] [INFO] --- deploy:3.1.4:deploy (default-deploy) @ maven-test-app ---
[INFO] [INFO] Uploading to artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/1.0/maven-test-app-1.0.pom
[INFO] [INFO] Uploaded to artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/1.0/maven-test-app-1.0.pom (2.1 kB at 28 kB/s)
[INFO] [INFO] Uploading to artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/1.0/maven-test-app-1.0.jar
[INFO] [INFO] Uploaded to artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/1.0/maven-test-app-1.0.jar (2.8 kB at 73 kB/s)
[INFO] [INFO] Downloading from artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/maven-metadata.xml
[INFO] [INFO] Uploading to artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/maven-metadata.xml
[INFO] [INFO] Uploaded to artifactory: https://jfrog.example.com/artifactory/local/temp/maven-release-local/pl/example/maven-test-app/maven-metadata.xml (300 B at 8.6 kB/s)
[INFO] [INFO] ------------------------------------------------------------------------
[INFO] [INFO] BUILD SUCCESS
[INFO] [INFO] ------------------------------------------------------------------------
[INFO] [INFO] Total time:  1.769 s
[INFO] [INFO] Finished at: 2026-05-03T07:14:07Z
[INFO] [INFO] ------------------------------------------------------------------------
[INFO] Cleaning up after release...
[INFO] 
[INFO] ---------------------< pl.example:maven-test-app >----------------------
[INFO] Building maven-test-app 1.0-SNAPSHOT
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] ------------------------------------------------------------------------
[INFO] BUILD FAILURE
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  13.892 s
[INFO] Finished at: 2026-05-03T07:14:07Z
[INFO] ------------------------------------------------------------------------
[ERROR] Unknown lifecycle phase " -DskipTests". You must specify a valid lifecycle phase or a goal in the format <plugin-prefix>:<goal> or <plugin-group-id>:<plugin-artifact-id>[:<plugin-version>]:<goal>. Available lifecycle phases are: pre-clean, clean, post-clean, validate, initialize, generate-sources, process-sources, generate-resources, process-resources, compile, process-classes, generate-test-sources, process-test-sources, generate-test-resources, process-test-resources, test-compile, process-test-classes, test, prepare-package, package, pre-integration-test, integration-test, post-integration-test, verify, install, deploy, pre-site, site, post-site, site-deploy. -> [Help 1]
org.apache.maven.lifecycle.LifecyclePhaseNotFoundException: Unknown lifecycle phase " -DskipTests". You must specify a valid lifecycle phase or a goal in the format <plugin-prefix>:<goal> or <plugin-group-id>:<plugin-artifact-id>[:<plugin-version>]:<goal>. Available lifecycle phases are: pre-clean, clean, post-clean, validate, initialize, generate-sources, process-sources, generate-resources, process-resources, compile, process-classes, generate-test-sources, process-test-sources, generate-test-resources, process-test-resources, test-compile, process-test-classes, test, prepare-package, package, pre-integration-test, integration-test, post-integration-test, verify, install, deploy, pre-site, site, post-site, site-deploy.
    at org.apache.maven.lifecycle.internal.DefaultLifecycleExecutionPlanCalculator.calculateLifecycleMappings (DefaultLifecycleExecutionPlanCalculator.java:225)
    at org.apache.maven.lifecycle.internal.DefaultLifecycleExecutionPlanCalculator.calculateMojoExecutions (DefaultLifecycleExecutionPlanCalculator.java:197)
    at org.apache.maven.lifecycle.internal.DefaultLifecycleExecutionPlanCalculator.calculateExecutionPlan (DefaultLifecycleExecutionPlanCalculator.java:119)
    at org.apache.maven.lifecycle.internal.DefaultLifecycleExecutionPlanCalculator.calculateExecutionPlan (DefaultLifecycleExecutionPlanCalculator.java:135)
    at org.apache.maven.lifecycle.internal.builder.BuilderCommon.resolveBuildPlan (BuilderCommon.java:93)
    at org.apache.maven.lifecycle.internal.LifecycleModuleBuilder.buildProject (LifecycleModuleBuilder.java:100)
    at org.apache.maven.lifecycle.internal.LifecycleModuleBuilder.buildProject (LifecycleModuleBuilder.java:73)
    at org.apache.maven.lifecycle.internal.builder.singlethreaded.SingleThreadedBuilder.build (SingleThreadedBuilder.java:53)
    at org.apache.maven.lifecycle.internal.LifecycleStarter.execute (LifecycleStarter.java:118)
    at org.apache.maven.DefaultMaven.doExecute (DefaultMaven.java:261)
    at org.apache.maven.DefaultMaven.doExecute (DefaultMaven.java:173)
    at org.apache.maven.DefaultMaven.execute (DefaultMaven.java:101)
    at org.apache.maven.cli.MavenCli.execute (MavenCli.java:919)
    at org.apache.maven.cli.MavenCli.doMain (MavenCli.java:285)
    at org.apache.maven.cli.MavenCli.main (MavenCli.java:207)
    at jdk.internal.reflect.DirectMethodHandleAccessor.invoke (DirectMethodHandleAccessor.java:103)
    at java.lang.reflect.Method.invoke (Method.java:580)
    at org.codehaus.plexus.classworlds.launcher.Launcher.launchEnhanced (Launcher.java:255)
    at org.codehaus.plexus.classworlds.launcher.Launcher.launch (Launcher.java:201)
    at org.codehaus.plexus.classworlds.launcher.Launcher.mainWithExitCode (Launcher.java:361)
    at org.codehaus.plexus.classworlds.launcher.Launcher.main (Launcher.java:314)
[ERROR] 
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR] 
[ERROR] For more information about the errors and possible solutions, please read the following articles:
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/LifecyclePhaseNotFoundException
