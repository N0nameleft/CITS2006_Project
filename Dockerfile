# Use an official Linux base image (Ubuntu as an example)
FROM ubuntu:latest

# Update and install required packages
RUN apt-get update && apt-get install -y \
    yara \
    openssl \
    sudo \
    acl \
    python3-pip \
    python3-venv \
    gcc \
    build-essential \
    python3-dev \  
    curl \
    jq \
    && apt-get clean

# Create a symbolic link for python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Setup Python environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy Python requirements file and install packages
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy your project files
COPY rapido_bank /opt/rapido_bank
WORKDIR /opt/rapido_bank
RUN chmod +x /opt/rapido_bank/security_tools/start_services.sh

# Build and install the C extension
WORKDIR /opt/rapido_bank/security_tools
RUN gcc readmem.c -o readmem
RUN gcc test_malicious_payload.c -o test_malicious_payload

# Return to the main work directory
WORKDIR /opt/rapido_bank

# Create a non-root admin user for the bank security team
RUN useradd -m -s /bin/bash admin && \
    echo "admin:securepassword" | chpasswd && \
    usermod -aG sudo admin

# Add RapidoBank users and groups with passwords
RUN groupadd -r ceo && useradd -r -m -s /bin/bash -g ceo charles && echo "charles:securepassword" | chpasswd \
    && groupadd -r manager && useradd -r -m -s /bin/bash -g manager mathilde && echo "mathilde:securepassword" | chpasswd \
    && groupadd -r bankers && useradd -r -m -s /bin/bash -g bankers diego && echo "diego:securepassword" | chpasswd \
    && useradd -r -m -s /bin/bash -g bankers santiago && echo "santiago:securepassword" | chpasswd \
    && useradd -r -m -s /bin/bash -g bankers maria && echo "maria:securepassword" | chpasswd \
    && groupadd -r auditor && useradd -r -m -s /bin/bash -g auditor maxwell && echo "maxwell:securepassword" | chpasswd

# Set Access Control Lists (ACLs) to provide read and execute permissions for the manager group
RUN setfacl -m g:ceo:rwx /opt/rapido_bank/portfolios \
    && setfacl -m g:manager:rx /opt/rapido_bank/portfolios \
    && setfacl -m g:auditor:rx /opt/rapido_bank/portfolios

# Apply the same `rx` permissions to subdirectories for the manager
RUN setfacl -R -m u:diego:rwx -m g:ceo:rwx -m g:manager:rx -m g:auditor:rx -m g::0 -m o::0 /opt/rapido_bank/portfolios/diego \
    && setfacl -R -m u:santiago:rwx -m g:ceo:rwx -m g:manager:rx -m g:auditor:rx -m g::0 -m o::0 /opt/rapido_bank/portfolios/santiago \
    && setfacl -R -m u:maria:rwx -m g:ceo:rwx -m g:manager:rx -m g:auditor:rx -m g::0 -m o::0 /opt/rapido_bank/portfolios/maria

# Change ownership of directories to individual users with their own group
RUN chown -R charles:ceo /opt/rapido_bank \
    && chown -R :auditor /opt/rapido_bank/portfolios \
    && chown -R mathilde:manager /opt/rapido_bank/portfolios \
    && chown -R diego /opt/rapido_bank/portfolios/diego \
    && chown -R santiago /opt/rapido_bank/portfolios/santiago \
    && chown -R maria /opt/rapido_bank/portfolios/maria

# Change ownership to the admin user for other components
RUN chown -R admin:admin /opt/rapido_bank/security_tools \
    && chmod -R 750 /opt/rapido_bank/security_tools \
    && setfacl -R -m g:ceo:rx /opt/rapido_bank/security_tools \
    && chown -R admin:admin /opt/rapido_bank/logs \
    && chown -R admin:admin /opt/rapido_bank/backups \
    && chmod -R 700 /opt/rapido_bank/backups \
    && chown -R admin:admin /opt/rapido_bank/admin \
    && chmod -R 700 /opt/rapido_bank/admin 

# Create a non-authorized user for testing
RUN useradd -m -s /bin/bash mike && \
    echo "mike:testpassword" | chpasswd

# Switch to non-root admin user
USER admin

# Define environment variables if needed
ENV RAPIDO_HOME /opt/rapido_bank

WORKDIR /opt/rapido_bank/security_tools
# Default command to run when the container starts
CMD ["bash"]

