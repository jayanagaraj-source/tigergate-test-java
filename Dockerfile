# Deliberately insecure Dockerfile for container / IaC scanner validation.
# For Dockerfile the FINDING marker sits on the line ABOVE the instruction.
#
# Built so a CONTAINER IMAGE scan surfaces every class of finding in one image:
#
#   OS package CVEs  - EOL Java 8 / Alpine 3.9 base
#   Java CVEs        - the whole resolved dependency tree is baked in as real
#                      .jar files. Image scanners identify Java packages by
#                      reading JARs out of the layers, so a pom.xml alone yields
#                      ZERO Java findings in a container scan; the jars must
#                      physically be present.
#   Secrets          - ENV / ARG values plus .env, config/*.pem and the GCP
#                      service-account key copied in with the build context.
#   Misconfiguration - root user, chmod 777, exposed SSH, no HEALTHCHECK.
#
# Do not deploy. Build with:  docker build -t tigergate-test-java:fixture .

# ---------------------------------------------------------------------------
# Stage 1: resolve the Maven dependency tree (builder - not shipped)
# ---------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS deps

WORKDIR /build
COPY pom.xml ./

# Pull the FULL tree - direct and transitive, every scope - into /build/lib.
# These are the artifacts the container scan will report on, so the resolution
# has to happen here rather than being left to a pom.xml text parse.
RUN mvn -B -q dependency:copy-dependencies \
        -DincludeScope=test \
        -DoutputDirectory=/build/lib

COPY src/ ./src/
COPY tests/ ./tests/
RUN mvn -B -q compile test-compile

# ---------------------------------------------------------------------------
# Stage 2: the vulnerable runtime image - this is what gets scanned
# ---------------------------------------------------------------------------
# FINDING: IAC-170 CWE-1104 docker-eol-base-image (openjdk 8u212 on Alpine 3.9: EOL runtime and EOL distro, large OS CVE surface)
FROM openjdk:8u212-jdk-alpine

# FINDING: SEC-070 CWE-798 docker-secret-in-env
ENV API_KEY="sk_live_F1xTuR3F4k3K3yAbCdEfGhIjKl"
# FINDING: SEC-071 CWE-798 docker-secret-in-arg
ARG DB_PASSWORD="Sup3rS3cret!"
# FINDING: SEC-072 CWE-798 docker-aws-secret-in-env
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# FINDING: IAC-171 CWE-1104 docker-unpinned-package-versions
RUN apk add --no-cache curl bash wget openssl || true

# FINDING: IAC-172 CWE-494 docker-curl-pipe-shell
RUN curl -fsSL https://get.example.com/install.sh | sh || true

# FINDING: IAC-173 CWE-295 docker-wget-no-check-certificate
RUN wget --no-check-certificate -O /tmp/tool.tar.gz https://downloads.example.com/tool.tar.gz || true

# A real, reachable, vulnerable artifact: commons-collections 3.2.1 carries the
# InvokerTransformer gadget chain (CVE-2015-6420). Fetched over ADD so the
# "remote URL in ADD" rule still fires, and so the image gains one more
# detectable Java component outside /app/lib.
# FINDING: IAC-174 CWE-494 docker-add-remote-url
ADD https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar /opt/agent.jar

WORKDIR /app

# The resolved dependency JARs. This is what makes the Java CVEs visible to a
# container image scan at all.
# FINDING: SCA-023 CWE-1395 container-bundled-vulnerable-jars (31 resolved JARs incl. log4j-core 2.14.1, jackson-databind 2.9.8, xstream 1.4.10, struts2-core 2.5.30)
COPY --from=deps /build/lib/ /app/lib/

# Compiled fixture classes, so the image also carries first-party code.
COPY --from=deps /build/target/classes/ /app/target/classes/

# FINDING: IAC-175 CWE-538 docker-copy-everything-no-dockerignore (copies .env, keys, .git)
# FINDING: SEC-073 CWE-798 docker-secrets-baked-into-layer (.env, config/*.pem, config/gcp-service-account.json land in the image)
COPY . .

# FINDING: IAC-176 CWE-732 docker-chmod-777
RUN chmod -R 777 /app

# FINDING: IAC-177 CWE-284 docker-expose-ssh
EXPOSE 22
EXPOSE 8080

# FINDING: IAC-178 CWE-250 docker-explicit-root-user
USER root

# FINDING: IAC-179 CWE-693 docker-no-healthcheck (HEALTHCHECK absent)
# FINDING: IAC-180 CWE-250 docker-runs-as-root-final (no non-root USER before CMD)
CMD ["sh", "-c", "java -cp /app/target/classes:/app/lib/* AppTest"]
