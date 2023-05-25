FROM python:3.9

RUN touch dummy_file
RUN mkdir /app

WORKDIR /app

COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY ./ ./

ENTRYPOINT ["python", "app.py"]
