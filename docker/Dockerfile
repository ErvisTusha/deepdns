# Use multi-stage build for smaller image
FROM alpine:latest AS builder

# Set build arguments and labels
ARG VERSION="1.0"
ARG BUILD_DATE
ARG VCS_REF

# Add metadata labels
LABEL maintainer="Ervis Tusha <x.com/ET>" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.name="deepdns" \
      org.label-schema.description="Advanced DNS Enumeration Tool" \
      org.label-schema.schema-version="1.0"

# Set environment variables
ENV PATH="/app:${PATH}" \
    DEEPDNS_CONFIG="/app/config"

# Install required packages
RUN apk add --no-cache \
    bind-tools \
    curl \
    jq \
    git \
    openssl \
    bash \
    parallel \
    ca-certificates \
    && mkdir -p /app/config /app/output

# Create non-root user
RUN addgroup -S deepdns && adduser -S -G deepdns -s /bin/bash deepdns \
    && chown -R deepdns:deepdns /app

# Set working directory
WORKDIR /app

# Copy the script and make it executable
COPY --chown=deepdns:deepdns deepdns.sh /app/
RUN chmod +x /app/deepdns.sh

# Switch to non-root user
USER deepdns

# Create volumes
VOLUME ["/app/output", "/app/config"]

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD ["/app/deepdns.sh", "--version"] || exit 1

ENTRYPOINT ["/app/deepdns.sh"]
CMD ["--help"]