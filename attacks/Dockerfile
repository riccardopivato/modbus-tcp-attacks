FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pymodbus==3.7.0 scapy==2.6.1
COPY . .
