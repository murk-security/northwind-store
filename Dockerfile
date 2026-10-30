# Northwind Store — deliberately-vulnerable demo app.
# Zero runtime dependencies: just the Python standard library.
FROM python:3.12-slim

WORKDIR /app
COPY app.py ./
COPY templates/ ./templates/
COPY static/ ./static/

ENV HOST=0.0.0.0 PORT=8099
EXPOSE 8099

# Runs as the image's default user; serves on 0.0.0.0 inside the container.
# The compose file binds it to 127.0.0.1 on the host so it is not world-reachable.
CMD ["python3", "app.py"]
