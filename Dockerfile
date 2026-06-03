FROM python:3.12-slim

# System deps:
#  - libssl-dev / gcc          → paramiko (SSH)
#  - libhidapi-libusb0 / libusb → hidapi (USB-connected UPS via HID Power Device)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev gcc \
    libhidapi-libusb0 libusb-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Persistent data volume
RUN mkdir -p /data
VOLUME ["/data"]

# USB-connected UPS support: bind-mount the WHOLE host /dev (read-only is fine)
# and run --privileged, e.g.:
#   docker run -p 8080:8080 --privileged \
#     -v /dev:/dev:ro -v homelab-data:/data homelab-manger
# Why all of /dev, not just /dev/bus/usb: hidapi reads the UPS via its
# /dev/hidrawN node. A UPS re-enumerates to a NEW hidraw node over time; a
# /dev/bus/usb-only mount (or --device) misses /dev/hidraw* and only snapshots
# /dev at container start, so a re-enumerated UPS becomes invisible and every
# open fails until restart. A live /dev bind keeps the new node visible. :ro
# still permits opening device nodes (the kernel exempts char devices from the
# read-only check) and the USB reset / autosuspend writes go to usbfs/sysfs.

ENV DB_PATH=/data/homelab.db
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

# Container health: hit the unauthenticated /healthz (which also pings the DB).
# Uses ${PORT} so it follows a `-e PORT=` override. start-period covers the
# init_db + bootstrap on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'), timeout=4).status==200 else 1)"

# Shell form so ${PORT} expands from the environment — override with `-e PORT=1234`.
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT}
