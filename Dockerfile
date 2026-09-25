FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 STATE_FILE=/data/state.json
WORKDIR /app
COPY node_checker.py .
VOLUME /data
CMD ["python", "node_checker.py"]
