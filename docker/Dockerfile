FROM golang:1.11-alpine3.9

WORKDIR /go/src/github.com/yaoice/webhook-demo

COPY . /go/src/github.com/yaoice/webhook-demo

ENV CGO_ENABLED 0

RUN  go build -o /go/bin/webhook-demo cmd/main.go

FROM alpine:3.9

LABEL maintainer="iceyao"

# copy the go binaries from the building stage
COPY --from=0 /go/bin /go/bin

EXPOSE 443

ENTRYPOINT ["/go/bin/webhook-demo"]
