FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 HOST=0.0.0.0
WORKDIR /app
COPY app.py /app/app.py
COPY fixtures /app/fixtures
RUN addgroup -S scanner && adduser -S -G scanner scanner && chown -R scanner:scanner /app
USER scanner
EXPOSE 8080
CMD ["python", "app.py"]
