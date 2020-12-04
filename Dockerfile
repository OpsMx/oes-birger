FROM golang:1.15.1-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/server server/server.go
RUN go build -o /out/agent agent/agent.go
RUN go build -o /out/sender sender/sender.go
FROM scratch AS bin
COPY --from=build /out/server /
