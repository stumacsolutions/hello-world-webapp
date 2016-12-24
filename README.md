This is a simple hello world application built using Spring Boot. It's 
main function is to act as a testing area for gradle, Spring Boot and 
the use of Snap CI to create a continuous deployment pipeline into an 
AWS environment orchestrated by Docker Cloud.

To deploy into your own Docker Cloud environment click the button below:

[![Deploy to Docker Cloud](https://files.cloud.docker.com/images/deploy-to-dockercloud.svg)](https://cloud.docker.com/stack/deploy/)

[![Build Status](https://snap-ci.com/stumacsolutions/hello-world-webapp/branch/master/build_image)](https://snap-ci.com/stumacsolutions/hello-world-webapp/branch/master)
[![codecov](https://codecov.io/gh/stumacsolutions/hello-world-webapp/branch/master/graph/badge.svg)](https://codecov.io/gh/stumacsolutions/hello-world-webapp)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/5ab4d3e898194a6eaef4e80dbc556934)](https://www.codacy.com/app/stumacsolutions/hello-world-webapp?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stumacsolutions/hello-world-webapp&amp;utm_campaign=Badge_Grade)
[![Code Climate](https://codeclimate.com/github/stumacsolutions/hello-world-webapp/badges/gpa.svg)](https://codeclimate.com/github/stumacsolutions/hello-world-webapp)
[![Issue Count](https://codeclimate.com/github/stumacsolutions/hello-world-webapp/badges/issue_count.svg)](https://codeclimate.com/github/stumacsolutions/hello-world-webapp)

# Build Pipeline

The Snap CI pipeline for this project can be found here:
https://snap-ci.com/stumacsolutions/hello-world-webapp/branch/master

# Live Environment
The application is deployed to an AWS node managed by Docker Cloud:
http://lb.hello-world-webapp.fb305fe4.svc.dockerapp.io (user/password)

The pipeline creates and pushes a Docker container to a Docker Hub
registry which can be found here:
https://hub.docker.com/r/stumacsolutions/hello-world-webapp

The .gradle and build folders are collected as artifacts on every stage
of the pipeline. These are automatically made available to all subsequent
stages automatically by Snap CI. The advantage of this approach is that
it leverages the incremental building capabilities of Gradle, without
feeling the need to squash multiple activities into a single stage of the 
pipeline to avoid the repetition of tasks such as compilation.

# Gradle Commands
This section documents custom Gradle commands built into this project.
Those tasks provided automatically by the various plugins which have 
been incorporated are not documented here.

## ./gradlew acceptanceTest
This command will run the acceptance tests for the project. Cucumber has
been used to implement acceptance tests. The Gherkin feature files are
located under src/test/resources/features. The Java code implementing 
the steps is located under src/test/java/acceptance/steps.

## ./gradlew assembleContainer
This command will build a Docker container holding the Spring Boot 
application. This command relies on Docker being available on the host
running the command.

## ./gradlew checkstyle
This command is a simple convenience command which wraps up the tasks 
provided by the checkstyle plugin.

## ./gradlew findbugs
This command is a simple convenience command which wraps up the tasks 
provided by the findbugs plugin.

## ./gradlew jdepend
This command is a simple convenience command which wraps up the tasks 
provided by the jdepend plugin.

## ./gradlew mutationTest
This command will perform mutation testing on the project. This ensures
that the tests are of a high standard and are performing meaningful
assertions.

## ./gradlew publishContainer
This command will publish the Docker container produced by the 
assembleContainer task. This command relies on Docker being available 
on the host running the command. The following environment variables are 
also required
* DOCKER_EMAIL = The email address for the registry into which to publish.
* DOCKER_USER  = The username for the registry into which to publish.
* DOCKER_PASS  = The password for the registry into which to publish.
