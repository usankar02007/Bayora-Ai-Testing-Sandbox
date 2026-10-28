FROM python:3.12-slim

RUN useradd --create-home --shell /usr/sbin/nologin sandboxuser

WORKDIR /app

USER sandboxuser

CMD ["python", "-c", "print('Bayora sandbox container is running')"]