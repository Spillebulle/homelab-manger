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

# USB-connected UPS support: to let the `usbups` adapter read a UPS plugged
# into the host, give the container access to the host USB tree at run time.
# Prefer a BIND MOUNT over --device: cheap UPS USB stacks periodically
# re-enumerate (new /dev/bus/usb devnum), and --device only maps nodes that
# existed at container start — so a re-enumerated UPS becomes invisible and
# every open fails until restart. A bind mount keeps new nodes visible:
#   docker run -p 8080:8080 \
#     -v /dev/bus/usb:/dev/bus/usb \
#     --device-cgroup-rule='c 189:* rmw' \
#     -v homelab-data:/data homelab-manger
# (189 = USB major; or just use --privileged). The process opens the device's
# hidraw node and may issue a USBDEVFS_RESET to recover a wedged UPS, both of
# which need root in the container (the default here) plus the cgroup access
# above.

ENV DB_PATH=/data/homelab.db
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

# Shell form so ${PORT} expands from the environment — override with `-e PORT=1234`.
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT}
