FROM golang:1.24-bookworm AS builder

RUN apt-get update && apt-get install -y clang llvm libbpf-dev gcc git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .

# Compile BPF (Target BPF architecture)
RUN clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c src/bpf_program.c -o bpf_program.o

# Compile Go Binary
RUN CGO_ENABLED=0 GOOS=linux go build -o sniffer_app .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates curl
WORKDIR /root/
COPY --from=builder /app/sniffer_app .
COPY --from=builder /app/bpf_program.o .
# Install Known API Database (JA4 signatures)
RUN curl -o ja4plus-mapping.csv https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv

CMD ["./sniffer_app"]
