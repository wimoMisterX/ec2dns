FROM python:3.9 as builder
COPY requirements.txt /
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.9-slim
COPY --from=builder /usr/local/lib/python3.9/site-packages/ /usr/local/lib/python3.9/site-packages/
COPY server.py /
ENTRYPOINT ["python", "server.py"]
