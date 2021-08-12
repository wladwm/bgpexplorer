FROM rust:1.54 as builder
WORKDIR /usr/src/bgpexplorer
COPY . .
RUN cargo build --release

FROM debian:buster-slim
#RUN apt-get update && rm -rf /var/lib/apt/lists/*
RUN rm -rf /var/lib/apt/lists/*
RUN mkdir -p /usr/bgpexplorer/contrib
COPY --from=builder /usr/src/bgpexplorer/contrib/* /usr/bgpexplorer/contrib/
COPY --from=builder /usr/src/bgpexplorer/target/release/bgpexplorer /usr/src/bgpexplorer/bgpexplorer.ini /usr/src/bgpexplorer/whois.json /usr/bgpexplorer/
WORKDIR /usr/bgpexplorer
EXPOSE 8080 179 623
CMD ["/usr/bgpexplorer/bgpexplorer"]

