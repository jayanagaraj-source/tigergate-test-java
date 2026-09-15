# Deliberately insecure Dockerfile for container / IaC scanner validation.
# For Dockerfile the FINDING marker sits on the line ABOVE the instruction.

# FINDING: IAC-170 CWE-1104 docker-eol-base-image (openjdk:8-jdk-alpine is EOL, alpine 3.9, many CVEs)
FROM openjdk:8-jdk-alpine

# FINDING: SEC-070 CWE-798 docker-secret-in-env
ENV API_KEY="sk_live_F1xTuR3F4k3K3yAbCdEfGhIjKl"
# FINDING: SEC-071 CWE-798 docker-secret-in-arg
ARG DB_PASSWORD="Sup3rS3cret!"
# FINDING: SEC-072 CWE-798 docker-aws-secret-in-env
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# FINDING: IAC-171 CWE-1104 docker-unpinned-package-versions
RUN apk add --no-cache curl bash wget openssl

# FINDING: IAC-172 CWE-494 docker-curl-pipe-shell
RUN curl -fsSL https://get.example.com/install.sh | sh

# FINDING: IAC-173 CWE-295 docker-wget-no-check-certificate
RUN wget --no-check-certificate -O /tmp/tool.tar.gz https://downloads.example.com/tool.tar.gz

# FINDING: IAC-174 CWE-494 docker-add-remote-url
ADD https://downloads.example.com/agent.jar /opt/agent.jar

WORKDIR /app
# FINDING: IAC-175 CWE-538 docker-copy-everything-no-dockerignore (copies .env, keys, .git)
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
CMD ["sh", "-c", "java -cp /app/target/classes AppTest"]
