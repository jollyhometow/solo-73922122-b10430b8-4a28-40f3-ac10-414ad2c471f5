FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY witness /app/witness
COPY archive /app/archive
COPY keys /app/keys

# Both services run from this one image with different commands. The signing
# private key ships only to the witness; the archive gets only the public key.
RUN chmod 600 /app/keys/witness_ed25519.pem && \
    chmod 644 /app/keys/witness_ed25519.pub.pem

EXPOSE 8000 8001
