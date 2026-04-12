FROM ubuntu:22.04

RUN apt-get update && apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd

# Create test account
ARG SSH_USER=redteam-test
ARG SSH_PASSWORD=RedteamPass123!
RUN useradd -m -s /bin/bash ${SSH_USER} && \
    echo "${SSH_USER}:${SSH_PASSWORD}" | chpasswd

# Configure SSH for brute-force simulation
RUN cat >> /etc/ssh/sshd_config <<EOF

# RedTeam simulation config
Port 2222
PasswordAuthentication yes
PermitRootLogin no
MaxAuthTries 100
MaxStartups 100:30:200
LoginGraceTime 120
UsePAM yes
EOF

EXPOSE 2222

CMD ["/usr/sbin/sshd", "-D", "-e"]
