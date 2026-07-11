# Build Go backend
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
WORKDIR /app
ARG TARGETOS
ARG TARGETARCH
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o main .

# Run stage
FROM alpine:latest
RUN apk add --no-cache tzdata
ENV TZ=Asia/Ho_Chi_Minh
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8082
ENTRYPOINT ["./main"]
