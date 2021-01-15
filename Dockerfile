FROM python:3.9
COPY requirements.txt /
RUN pip install -r requirements.txt
COPY server.py /
ENTRYPOINT ["python", "server.py"]
