FROM python:3.11-alpine

# cloudflared — détection auto de l'architecture
RUN apk add --no-cache curl && \
    ARCH=$(uname -m) && \
    case "$ARCH" in \
      aarch64)        CF_ARCH="arm64" ;; \
      armv7l|armhf)   CF_ARCH="arm"   ;; \
      *)              CF_ARCH="amd64" ;; \
    esac && \
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" \
    -o /usr/local/bin/cloudflared && \
    chmod +x /usr/local/bin/cloudflared

RUN pip install --no-cache-dir paho-mqtt requests certifi
COPY main.py /main.py
CMD ["python", "-u", "/main.py"]
