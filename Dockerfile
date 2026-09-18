FROM python:3.12-slim

# Run as an unprivileged user: a compromised container should not be root.
RUN useradd --create-home sentinel
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R sentinel:sentinel /app
USER sentinel

# Inside a container we must listen on all interfaces; publish the port to
# localhost only:  docker run -p 127.0.0.1:5050:5050 sentinel-soc
ENV SENTINEL_HOST=0.0.0.0
EXPOSE 5050
CMD ["python", "run.py", "demo"]
