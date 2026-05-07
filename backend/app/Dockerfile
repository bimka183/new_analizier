FROM golang:1.25.5-alpine AS builder

RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY backend/ ./backend/
COPY src/ ./src/

RUN CGO_ENABLED=1 GOOS=linux go build -o /app/server ./backend/app/

FROM alpine:latest

RUN apk --no-cache add ca-certificates libpcap

WORKDIR /app

COPY --from=builder /app/server .
RUN mkdir -p /app/files

EXPOSE 8080

CMD ["./server"]
