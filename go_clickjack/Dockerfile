from golang:latest

MAINTAINER Daniel Roberts "danny@erebus.cymru"

ENV CONTAINER=TRUE

WORKDIR /app

RUN wget https://github.com/DannyCymru/CyberSecTools/releases/download/go_clickjack/clickjack

RUN chmod +x clickjack

EXPOSE 9999/tcp

ENTRYPOINT ["./clickjack"]