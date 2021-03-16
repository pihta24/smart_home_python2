FROM python:3.6-alpine

RUN adduser -D smartHome

WORKDIR /home/smart-home

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY templates templates
COPY static static
COPY app.py ./
COPY wsgi.py ./

ENV FLASK_APP app.py

RUN chown -R smartHome:smartHome ./
USER smartHome

EXPOSE 5000
ENTRYPOINT gunicorn --bind 0.0.0.0:5000 wsgi:app --workers=3