FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/opnsense-uxg ./cmd/opnsense-uxg
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opnsense-uxg /opnsense-uxg
COPY --from=build --chown=65532:65532 /data /data
WORKDIR /data
VOLUME /data
ENTRYPOINT ["/opnsense-uxg"]
CMD ["-serve", "-config", "/data/config.yaml"]
