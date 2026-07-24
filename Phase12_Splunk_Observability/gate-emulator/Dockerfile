FROM python:3.9-slim
WORKDIR /app
RUN pip install --no-cache-dir bacpypes
COPY gate_server.py .
CMD ["python", "gate_server.py"]
