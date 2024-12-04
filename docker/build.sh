#!/usr/bin/env bash

# Strict error handling
set -euo pipefail
trap 'echo "Error on line $LINENO" >&2' ERR

# Script variables
readonly IMAGE_NAME="deepdns"
readonly CONTAINER_NAME="deepdns-scanner"
readonly VERSION="1.0"
readonly BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
readonly VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build arguments as a string instead of array
DOCKER_BUILD_ARGS="--build-arg VERSION=${VERSION} --build-arg BUILD_DATE=${BUILD_DATE} --build-arg VCS_REF=${VCS_REF}"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

# Function to display usage
SHOW_USAGE() {
    echo -e "\n${BOLD}Usage:${NC}"
    echo -e "  ${YELLOW}./build.sh${NC} [command]"
    echo -e "\n${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}build${NC}     Build Docker image"
    echo -e "  ${GREEN}run${NC}       Run Docker container"
    echo -e "  ${GREEN}clean${NC}     Remove Docker container and image"
    echo -e "  ${GREEN}help${NC}      Show this help message"
}

# Function to check Docker installation
CHECK_DOCKER() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Docker is not installed"
        exit 1
    fi
}

# Function to build Docker image with progress
BUILD_IMAGE() {
    echo -e "\n${GREEN}${BOLD}[+]${NC} Building Docker image: $IMAGE_NAME:$VERSION"
    
    # Change to parent directory to include deepdns.sh in build context
    cd "$(dirname "$0")/.."
    
    echo -e "${GREEN}[*]${NC} Building image..."
    docker build \
        --build-arg "VERSION=${VERSION}" \
        --build-arg "BUILD_DATE=${BUILD_DATE}" \
        --build-arg "VCS_REF=${VCS_REF}" \
        -t "${IMAGE_NAME}:${VERSION}" \
        -t "${IMAGE_NAME}:latest" \
        -f docker/Dockerfile . || {
            echo -e "${RED}${BOLD}[ERROR]${NC} Build failed!"
            exit 1
        }
}

# Enhanced run container function with resource limits
RUN_CONTAINER() {
    echo -e "\n${GREEN}${BOLD}[+]${NC} Running DeepDNS container"
    docker run --rm -it \
        --name "$CONTAINER_NAME" \
        --cpu-shares=1024 \
        --memory=2g \
        --memory-swap=2g \
        --security-opt=no-new-privileges \
        -v "$(pwd)/output:/app/output:rw" \
        -v "$(pwd)/config:/app/config:ro" \
        --network host \
        "$IMAGE_NAME:$VERSION" "$@"
}

# Function to clean up
CLEAN_UP() {
    echo -e "\n${YELLOW}${BOLD}[!]${NC} Cleaning up Docker resources"
    docker stop "$CONTAINER_NAME" 2>/dev/null
    docker rm "$CONTAINER_NAME" 2>/dev/null
    docker rmi "$IMAGE_NAME:$VERSION" 2>/dev/null
}

# Main execution
COMMAND=${1:-"help"}  # Set default command to "help" if no argument provided

case "$COMMAND" in
    "build")
        CHECK_DOCKER
        BUILD_IMAGE
        ;;
    "run")
        shift || true  # Safely handle shift even if no more arguments
        CHECK_DOCKER
        RUN_CONTAINER "$@"
        ;;
    "clean")
        CLEAN_UP
        ;;
    "help" | *)
        SHOW_USAGE
        ;;
esac

exit 0