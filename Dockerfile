# syntax=docker/dockerfile:1
#
#   docker build -t vulncheck .
#   docker run --rm -v "$PWD:/workspace" vulncheck --fail-on reachable
#
# The project must be compiled (e.g. `MIX_ENV=prod mix compile`) before the
# scan for function-level reachability; without a build directory the scan
# falls back to package-level verdicts.

ARG ELIXIR_VERSION=1.18.4
ARG OTP_VERSION=27.3.4.16
ARG ALPINE_VERSION=3.22.5

FROM hexpm/elixir:${ELIXIR_VERSION}-erlang-${OTP_VERSION}-alpine-${ALPINE_VERSION} AS builder

ENV MIX_ENV=prod
WORKDIR /src

COPY mix.exs mix.lock ./
COPY lib lib
RUN mix escript.build && ./vulncheck --version

FROM hexpm/erlang:${OTP_VERSION}-alpine-${ALPINE_VERSION} AS runtime

# git serves --diff; the mounted workspace belongs to another user, so git
# must trust it explicitly
RUN apk add --no-cache ca-certificates git \
    && git config --system --add safe.directory '*' \
    && addgroup -S vulncheck \
    && adduser -S -G vulncheck -h /home/vulncheck vulncheck

COPY --from=builder /src/vulncheck /usr/local/bin/vulncheck

ENV LANG=C.UTF-8
USER vulncheck
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/vulncheck"]
