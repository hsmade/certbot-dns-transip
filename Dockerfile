FROM python:3.9
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
