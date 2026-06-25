FROM python:3.11-alpine
RUN pip install --no-cache-dir paho-mqtt requests certifi
COPY main.py /main.py
CMD ["python", "-u", "/main.py"]
