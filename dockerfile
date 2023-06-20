FROM python:3.9.17-alpine3.18
WORKDIR /autonmap
COPY . /autonmap
RUN apk add nmap
RUN pip install -r requirements.txt
ENTRYPOINT ["python","autonmap.py"]
