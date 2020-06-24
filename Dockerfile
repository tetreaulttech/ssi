# The base go-image
FROM golang:1.13-alpine

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum /app/
RUN go mod download
COPY . /app
RUN go build -o server /app/agent/

# Run the server executable
CMD [ "/app/server" ]