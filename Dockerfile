FROM golang:1.21-alpine
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /dragonauth ./cmd/main.go
EXPOSE 8080
CMD ["/dragonauth"]
