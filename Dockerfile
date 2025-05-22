# syntax = docker/dockerfile:1.4

FROM golang:1.24.3 as build
WORKDIR /go
COPY go.* .
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o app -ldflags="-w -s" .


FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --link /go/app /app
ENTRYPOINT ["/app"]
