FROM kalilinux/kali-rolling:latest

LABEL maintainer="auto-redteam"
LABEL description="Non-destructive red team simulation runner — approved tools only"

# Install only approved, non-destructive tools
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    openssh-client \
    nmap \
    netcat-traditional \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY simulate.py .
COPY scenarios/ ./scenarios/

# Run as non-root
RUN useradd -m -s /bin/bash runner
USER runner

ENTRYPOINT ["python3", "simulate.py"]
