FROM python:3.7-alpine
RUN mkdir /app
COPY requirements.txt ./app
COPY app.py ./app
COPY models.py ./app
COPY resources.py ./app
COPY views.py ./app
RUN pip install -r /app/requirements.txt
WORKDIR /app
EXPOSE 5000
CMD ["gunicorn" , "-b", "0.0.0.0:5000", "app:app"]