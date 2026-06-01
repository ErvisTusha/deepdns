#!/bin/bash

# Add error handling
set -euo pipefail
trap 'echo "Error on line $LINENO" >&2' ERR

# Function to clean temporary files and logs
CLEANUP_FILES() {
    printf "\033[1;32m[+]\033[0m Cleaning up temporary files and logs...\n"
    rm -f "$TEMP_FILE" 2>/dev/null || true
    find "$RELEASES_DIR" -maxdepth 1 -type f -name "temp_deepdns*.sh" -delete 2>/dev/null || true
    find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name "deepdns-tests.*" -exec rm -rf {} + 2>/dev/null || true
}

# Set script variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
RELEASES_DIR="$SCRIPT_DIR/releases"
MAIN_DIR="$(dirname "$SCRIPT_DIR")" # Parent directory of dev
TEMP_FILE="$RELEASES_DIR/temp_deepdns.sh"
FINAL_FILE="$MAIN_DIR/deepdns.sh" # Changed path to parent directory
TEST_SCRIPT="$SCRIPT_DIR/test/test.sh"
BASHFRAME_FILE="$SCRIPT_DIR/vendor/bashframe.sh"
BASHFRAME_FUNCTIONS="LOG IS_INSTALLED DOWNLOAD ASK_USER IS_EMPTY IS_NUMBER VAL_IP FILE_EXISTS FILE_EMPTY IS_READABLE IS_WRITABLE GENERATE_RANDOM"

# Create release directory
mkdir -p "$RELEASES_DIR"

CHECK_PERMISSIONS() {
    local DIR="$1"
    if [ ! -w "$DIR" ]; then
        printf "\033[1;31m[!]\033[0m No write permission in %s\n" "$DIR"
        exit 1
    fi
}

CHECK_PERMISSIONS "$RELEASES_DIR"
CHECK_PERMISSIONS "$MAIN_DIR"

# Clean up before starting
CLEANUP_FILES

# Get current version from settings.sh
CURRENT_VERSION=$(grep "VERSION=" "$SCRIPT_DIR/config/settings.sh" | cut -d'"' -f2)

# Update version prompt with validation
printf "\033[1;36m[?]\033[0m Current version is: \033[1;33m%s\033[0m\n" "$CURRENT_VERSION"
printf "\033[1;36m[?]\033[0m Enter new version number (press enter to keep current): "
read -r NEW_VERSION

if [ -z "$NEW_VERSION" ]; then
    NEW_VERSION=$CURRENT_VERSION
fi

printf "\033[1;32m[+]\033[0m Preparing release version \033[1;33m%s\033[0m\n" "$NEW_VERSION"

# Start with a clean file
: >"$TEMP_FILE"

# Add shebang and header
cat >"$TEMP_FILE" <<'EOF'
#!/bin/bash
#
######################################################################
#         DeepDNS - Advanced DNS Enumeration Script                  #
#  Author: Ervis Tusha               X: htts://x.com/ET              #
#  License: MIT        GitHub: https://github.com/ErvisTusha/deepdns #
######################################################################
#
EOF

# Function to extract content between first and last line
EXTRACT_CONTENT() {
    local FILE="$1"
    # Use grep to exclude shebang and empty source lines
    grep -v '^#\!/bin/bash$' "$FILE" | grep -v '^$' | grep -v '^source'
}

EXTRACT_FUNCTION() {
    local FILE="$1"
    local FUNCTION_NAME="$2"

    awk -v fn="$FUNCTION_NAME" '
        $0 ~ "^" fn "\\(\\)[[:space:]]*\\{" {
            in_function = 1
            found = 1
        }
        in_function {
            line = $0
            sub(/[[:space:]]+$/, "", line)
            print line
            if ($0 == "}") {
                exit
            }
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$FILE"
}

# Combine files in the correct order
printf "\033[1;32m[+]\033[0m Combining source files...\n"
sed -i "s/VERSION=\"$CURRENT_VERSION\"/VERSION=\"$NEW_VERSION\"/" "$SCRIPT_DIR/config/settings.sh"

# Add only the BashFrame functions used by DeepDNS.
if [ ! -f "$BASHFRAME_FILE" ]; then
    printf "\033[1;31m[!]\033[0m BashFrame file not found: %s\n" "$BASHFRAME_FILE"
    rm -f "$TEMP_FILE"
    exit 1
fi

echo "" >>"$TEMP_FILE"
echo "# From BashFrame selected functions" >>"$TEMP_FILE"
for FUNCTION_NAME in $BASHFRAME_FUNCTIONS; do
    printf "\033[1;32m[+]\033[0m Adding BashFrame function: %s\n" "$FUNCTION_NAME"
    if ! EXTRACT_FUNCTION "$BASHFRAME_FILE" "$FUNCTION_NAME" >>"$TEMP_FILE"; then
        printf "\033[1;31m[!]\033[0m Missing BashFrame function: %s\n" "$FUNCTION_NAME"
        rm -f "$TEMP_FILE"
        exit 1
    fi
    echo "" >>"$TEMP_FILE"
done

# First add settings - with version replacement
echo "" >>"$TEMP_FILE"
EXTRACT_CONTENT "$SCRIPT_DIR/config/settings.sh" >>"$TEMP_FILE"
echo "" >>"$TEMP_FILE"

# Update version in settings.sh
sed -i "s/VERSION=\"$CURRENT_VERSION\"/VERSION=\"$NEW_VERSION\"/" "$SCRIPT_DIR/config/settings.sh"

# Update version in README.md
README_PATH="$MAIN_DIR/README.md"
if [ -f "$README_PATH" ]; then
    printf "\033[1;32m[+]\033[0m Updating version in README.md...\n"
    # Update version in badge URL
    sed -i "s/version-[0-9.]\+-blue/version-${NEW_VERSION}-blue/g" "$README_PATH"
else
    printf "\033[1;31m[!]\033[0m README.md not found at: %s\n" "$README_PATH"
fi

# Define library files list and add libraries
LIBRARY_FILES="core.sh utils.sh validation.sh dns.sh passive.sh active.sh pentest.sh scan.sh"

# Add library files in order
for LIB in $LIBRARY_FILES; do
    if [ -f "$SCRIPT_DIR/lib/$LIB" ]; then
        printf "\033[1;32m[+]\033[0m Adding library: %s\n" "$LIB"
        echo "" >>"$TEMP_FILE"
        echo "# From $LIB" >>"$TEMP_FILE"
        EXTRACT_CONTENT "$SCRIPT_DIR/lib/$LIB" >>"$TEMP_FILE"
        echo "" >>"$TEMP_FILE"
    else
        printf "\033[1;31m[!]\033[0m Missing library file: %s\n" "$LIB"
        exit 1
    fi
done

# Add main script content
printf "\033[1;32m[+]\033[0m Adding main script...\n"
echo "" >>"$TEMP_FILE"
grep -v '^#\!/bin/bash$' "$SCRIPT_DIR/deepdns" | grep -v '^source' >>"$TEMP_FILE"

# Ensure there's a newline at the end of file
echo "" >>"$TEMP_FILE"

# Make the script executable
chmod +x "$TEMP_FILE"

# Optional: Create a backup of the previous version
BACKUP_FILE="$RELEASES_DIR/deepdns-$CURRENT_VERSION.sh"
if [ -f "$BACKUP_FILE" ]; then
    printf "\033[1;33m[!]\033[0m Backup already exists. Overwrite? [y/N]: "
    read -r RESPONSE
    if [[ "$RESPONSE" =~ ^[Yy]$ ]]; then
        cp "$FINAL_FILE" "$BACKUP_FILE"
        printf "\033[1;32m[+]\033[0m Backup updated\n"
    else
        printf "\033[1;33m[!]\033[0m Using existing backup\n"
    fi
else
    cp "$FINAL_FILE" "$BACKUP_FILE"
    printf "\033[1;32m[+]\033[0m Created backup of previous version\n"
fi

# Validate the generated script
if bash -n "$TEMP_FILE"; then
    printf "\033[1;32m[+]\033[0m Syntax check passed\n"
    if [ ! -f "$TEST_SCRIPT" ]; then
        printf "\033[1;31m[!]\033[0m Unit test script not found: %s\n" "$TEST_SCRIPT"
        rm -f "$TEMP_FILE"
        exit 1
    fi

    printf "\033[1;32m[+]\033[0m Running unit tests...\n"
    if ! bash "$TEST_SCRIPT"; then
        printf "\033[1;31m[!]\033[0m Unit tests failed\n"
        rm -f "$TEMP_FILE"
        exit 1
    fi

    printf "\033[1;32m[+]\033[0m Unit tests passed\n"
    if mv "$TEMP_FILE" "$FINAL_FILE"; then
        printf "\033[1;32m[+]\033[0m Moved release to main directory: %s\n" "$MAIN_DIR"
    else
        printf "\033[1;31m[!]\033[0m Failed to move release file to main directory\n"
        rm -f "$TEMP_FILE"
        exit 1
    fi
else
    printf "\033[1;31m[!]\033[0m Syntax check failed\n"
    rm -f "$TEMP_FILE"
    exit 1
fi

printf "\033[1;32m[✓]\033[0m Release prepared successfully!\n"
printf "\033[1;32m[i]\033[0m Output file: %s\n" "$FINAL_FILE"
printf "\033[1;32m[i]\033[0m Version: %s\n" "$NEW_VERSION"
