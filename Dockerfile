# Build Go backend
FROM golang:alpine AS builder
WORKDIR /app
COPY backend/go.mod ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Run stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8082
ENTRYPOINT ["./main"]
