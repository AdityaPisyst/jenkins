# Use official Jenkins LTS image
FROM jenkins/jenkins:lts

# Switch to root to install dependencies
USER root

# Install Git (needed for Jenkins to work with GitHub)
RUN apt-get update && apt-get install -y git

# Switch back to Jenkins user
USER jenkins

# Expose Jenkins web interface and agent ports
EXPOSE 8080 50000
