FROM python:3.9
RUN mkdir usr/app
WORKDIR usr/app

COPY . .
RUN pip install -r requirements.txt

CMD python app.py

#COPY start_server.sh /usr/src/app/

#ENTRYPOINT ["sh", "/usr/src/app/start_server.sh"]
