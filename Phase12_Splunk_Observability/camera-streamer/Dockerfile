FROM alpine:latest
RUN apk add --no-cache ffmpeg tzdata font-dejavu
WORKDIR /app
COPY stream.sh .
RUN chmod +x stream.sh
CMD ["./stream.sh"]
