# Use an official Linux base image (Ubuntu as an example)
FROM ubuntu:latest

# Update and install required packages
RUN apt-get update && apt-get install -y \
    yara \
    openssl \
    sudo \
    python3-pip \
    && apt-get clean

# Create a non-root admin user for the bank security team
RUN useradd -m -s /bin/bash admin && \
    echo "admin:securepassword" | chpasswd && \
    usermod -aG sudo admin

# Create directories for the required components
RUN mkdir -p /opt/rapido_bank/yara_rules \
    && mkdir -p /opt/rapido_bank/cipher \
    && mkdir -p /opt/rapido_bank/logs \
    && mkdir -p /opt/rapido_bank/encrypted \
    && mkdir -p /opt/rapido_bank/hash

# Change ownership to the admin user
RUN chown -R admin:admin /opt/rapido_bank

# Switch to non-root user
USER admin

# Define environment variables if needed
ENV RAPIDO_HOME /opt/rapido_bank

# Default command to run when the container starts
CMD ["bash"]

