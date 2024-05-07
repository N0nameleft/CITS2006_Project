# Use an official Linux base image (Ubuntu as an example)
FROM ubuntu:latest

# Update and install required packages
RUN apt-get update && apt-get install -y \
    yara \
    openssl \
    sudo \
    acl \
    python3-pip \
    curl \
    jq \
    && apt-get clean

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

# Create directories for the required components, including portfolios and shared folders
RUN mkdir -p /opt/rapido_bank/yara_rules \
    && mkdir -p /opt/rapido_bank/cipher \
    && mkdir -p /opt/rapido_bank/logs \
    && mkdir -p /opt/rapido_bank/encrypted \
    && mkdir -p /opt/rapido_bank/hash \
    && mkdir -p /opt/rapido_bank/portfolios \
    && mkdir -p /opt/rapido_bank/portfolios/diego \
    && mkdir -p /opt/rapido_bank/portfolios/santiago \
    && mkdir -p /opt/rapido_bank/portfolios/maria \
    && mkdir -p /opt/rapido_bank/shared

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
RUN chown -R admin:admin /opt/rapido_bank/yara_rules \
    && chown -R admin:admin /opt/rapido_bank/cipher \
    && chown -R admin:admin /opt/rapido_bank/logs \
    && chown -R admin:admin /opt/rapido_bank/encrypted \
    && chown -R admin:admin /opt/rapido_bank/hash

# Switch to non-root admin user
USER admin

# Define environment variables if needed
ENV RAPIDO_HOME /opt/rapido_bank

# Default command to run when the container starts
CMD ["bash"]

