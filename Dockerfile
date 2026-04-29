# Minimal Dockerfile for rke2-patcher
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /rke2-patcher .

FROM registry.suse.com/bci/bci-busybox:16.0
COPY --from=builder /rke2-patcher /usr/local/bin/rke2-patcher
ENTRYPOINT ["sleep", "infinity"]
