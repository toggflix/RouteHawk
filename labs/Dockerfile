FROM python:3.12-slim

WORKDIR /app

COPY labs/demo_server.py /app/labs/demo_server.py

ENV ROUTEHAWK_LAB_HOST=0.0.0.0
ENV ROUTEHAWK_LAB_PORT=8088

EXPOSE 8088

CMD ["python", "/app/labs/demo_server.py"]
