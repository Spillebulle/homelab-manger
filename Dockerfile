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
# into the host, pass the USB device into the container at run time, e.g.
#   docker run --device=/dev/bus/usb -v homelab-data:/data -p 8080:8080 homelab-manger
# (or scope it to the specific bus/dev path). The process opens the device's
# hidraw node, which needs root in the container (the default here) or a host
# udev rule granting access.

ENV DB_PATH=/data/homelab.db
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

# Shell form so ${PORT} expands from the environment — override with `-e PORT=1234`.
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT}
