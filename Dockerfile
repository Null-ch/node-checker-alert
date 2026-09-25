FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 STATE_FILE=/data/state.json
WORKDIR /app
COPY node_checker ./node_checker
VOLUME /data
CMD ["python", "-m", "node_checker"]
