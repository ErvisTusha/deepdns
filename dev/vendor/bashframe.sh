#!/bin/bash
######################################################################
#                     BashFrame Extended 1.5.1                       #
######################################################################
#clear
# Global configuration
VERBOSE=false
DEBUG=false
DEBUG_LOG="/tmp/log/bashframe.log"
VERSION="1.5.1"
######################################################################
#                  1. User and Privilege Checks                      #
######################################################################

# Function: IS_SUDO
# Checks if the user has root or sudo privileges
IS_SUDO() {
    if [[ $EUID -eq 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: User has root privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User has root privileges" >>"$DEBUG_LOG"
        return 0
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO: User does not have root privileges"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User does not have root privileges" >>"$DEBUG_LOG"
    return 1
}

# Function: HAS_SUDO
# Checks if the user has sudo privileges
HAS_SUDO() {
    if sudo -n true 2>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: User has sudo privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User has sudo privileges" >>"$DEBUG_LOG"
        return 0
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO: User does not have sudo privileges"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User does not have sudo privileges" >>"$DEBUG_LOG"
    return 1
}

######################################################################
#                 2. Tool and Installation Management                #
######################################################################

# Function: IS_INSTALLED
# Checks if a package is installed
IS_INSTALLED() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No package name provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No package name provided" >>"$DEBUG_LOG"
        return 1
    fi

    if command -v "$1" &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Package $1 is installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Package $1 is installed" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Package $1 is not installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Package $1 is not installed" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: INSTALL
# Installs a package
# Function to install the script
INSTALL_SCRIPT() {
    local SCRIPT=""
    SCRIPT="$(basename "$0")"
    # Check if $1 is empty
    if [[ -z "$1" ]]; then
        INSTALL_DIR="/usr/local/bin"
    else
        # Check if $1 is a valid directory
        if ! [[ -d "$1" ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "ERROR:INSTALL_SCRIPT Invalid directory provided"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:INSTALL_SCRIPT Invalid directory provided" >>"$DEBUG_LOG"
            return 1
        fi
        INSTALL_DIR="$1"
    fi

    # Check if user has sudo privileges if now return 1
    if [[ "$EUID" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT User does not have root privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT User does not have root privileges" >>"$DEBUG_LOG"
        return 1
    fi

    # Check if the script is already installed
    if command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT $SCRIPT is already installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT $SCRIPT is already installed" >>"$DEBUG_LOG"
        return 0
    fi

    # install the script
    cp "$0" "$INSTALL_DIR/$SCRIPT"
    chmod +x "$INSTALL_DIR/$SCRIPT"

    # check if the script was installed successfully
    if ! command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:INSTALL_SCRIPT Failed to install $SCRIPT"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:INSTALL_SCRIPT Failed to install $SCRIPT" >>"$DEBUG_LOG"
        return 1
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT $SCRIPT installed successfully"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT $SCRIPT installed successfully" >>"$DEBUG_LOG"
    return 0
}

# Function: UNINSTALL
UNINSTALL_SCRIPT() {
    local SCRIPT="$1"
    local INSTALL_DIR="/usr/local/bin"

    # check if user has sudo privileges if now return 1
    if [[ "$EUID" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:UNINSTALL_SCRIPT User does not have root privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UNINSTALL_SCRIPT User does not have root privileges" >>"$DEBUG_LOG"
        return 1
    fi

    #check if the script is installed
    if ! command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:UNINSTALL_SCRIPT $SCRIPT is not installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UNINSTALL_SCRIPT $SCRIPT is not installed" >>"$DEBUG_LOG"
        return 1
    fi

    # uninstall the script
    rm "$INSTALL_DIR/$SCRIPT"

    # check if the script was uninstalled successfully
    if command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:UNINSTALL_SCRIPT Failed to uninstall $SCRIPT"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:UNINSTALL_SCRIPT Failed to uninstall $SCRIPT" >>"$DEBUG_LOG"
        return 1
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO:UNINSTALL_SCRIPT $SCRIPT uninstalled successfully"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UNINSTALL_SCRIPT $SCRIPT uninstalled successfully" >>"$DEBUG_LOG"
    return 0

}

# Function: UPDATE
# Updates
UPDATE() {

    #check if user has sudo privileges if now return 1
    if [[ "$EUID" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE User does not have root privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE User does not have root privileges" >>"$DEBUG_LOG"
        return 1
    fi

    #check if script is installed
    if ! command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE $SCRIPT is not installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE $SCRIPT is not installed" >>"$DEBUG_LOG"
        return 1
    fi

    # update the script
    [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE Updating $SCRIPT"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE Updating $SCRIPT" >>"$DEBUG_LOG"
    #download the latest version with curl or wget to /tmp/$SCRIPT
    if command -v curl >/dev/null 2>&1; then
        curl -L "$SCRIPT_URL" -o "/tmp/$SCRIPT"
    elif command -v wget >/dev/null 2>&1; then
        wget "$SCRIPT_URL" -O "/tmp/$SCRIPT"
    else
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:UPDATE curl or wget not found"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:UPDATE curl or wget not found" >>"$DEBUG_LOG"
        return 1
    fi

    # check if the downloaded file is empty
    if [ ! -s "/tmp/$SCRIPT" ]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:UPDATE Downloaded file is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:UPDATE Downloaded file is empty" >>"$DEBUG_LOG"
        return 1
    fi

    # move the downloaded file to /usr/local/bin
    cp "/tmp/$SCRIPT" "/usr/local/bin/$SCRIPT"
    chmod +x "/usr/local/bin/$SCRIPT"
    [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE $SCRIPT updated successfully"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE $SCRIPT updated successfully" >>"$DEBUG_LOG"
    return 0
}

# Function: DOWNLOAD
DOWNLOAD() {
    # Function to download files
    # Usage: DOWNLOAD <URL> [DESTINATION]

    local URL="$1"
    local DESTINATION="$2"

    if [[ -z "$URL" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No URL provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No URL provided" >>"$DEBUG_LOG"
        return 1
    fi

    if [[ -z "$DESTINATION" ]]; then
        DESTINATION_FILE="${URL##*/}"
        DESTINATION="${PWD}/${DESTINATION_FILE}"
    fi
    # Check if the destination folder is writable
    if ! IS_WRITABLE "$(dirname "$DESTINATION")"; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: Destination $DESTINATION is not writable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Destination $DESTINATION is not writable" >>"$DEBUG_LOG"
        return 1
    fi

    [[ "$VERBOSE" == "true" ]] && echo "INFO: Downloading $URL to $DESTINATION"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Downloading $URL to $DESTINATION" >>"$DEBUG_LOG"

    if command -v curl >/dev/null 2>&1; then
        curl -L "$URL" -o "$DESTINATION"
        STATUS=$?
    elif command -v wget >/dev/null 2>&1; then
        wget "$URL" -O "$DESTINATION"
        STATUS=$?
    else
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: curl or wget not found"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: curl or wget not found" >>"$DEBUG_LOG"
        return 1
    fi

    if [[ "$STATUS" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: Download failed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Download failed" >>"$DEBUG_LOG"
        return 1
    fi

    [[ "$VERBOSE" == "true" ]] && echo "INFO: Download successful"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Download successful" >>"$DEBUG_LOG"
    return 0
}

######################################################################
#                        3. User Interaction                         #
######################################################################

# Function: ASK_USER
# Asks the user for input
ASK_USER() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No question provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No question provided"
        return 1
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO: $1"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1" >>"$DEBUG_LOG"
    local QUESTION="$1"
    local MAX_ATTEMPTS="${2:-3}"
    local ANSWER
    local ATTEMPTS=0
    while true; do
        read -r -p "$QUESTION " ANSWER
        if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "INFO: User answered yes"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User answered yes" >>"$DEBUG_LOG"
            return 0
        elif [[ "$ANSWER" =~ ^[Nn]$ ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "INFO: User answered no"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User answered no" >>"$DEBUG_LOG"
            return 1
        else
            ((ATTEMPTS++))
            if [[ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]]; then
                [[ "$VERBOSE" == "true" ]] && echo "INFO: Maximum attempts reached"
                [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Maximum attempts reached" >>"$DEBUG_LOG"
                return 1
            fi
        fi
    done
}

######################################################################
#                         4. Variable Checks                         #
######################################################################

# Function: IS_EMPTY
# Checks if a variable is empty
IS_EMPTY() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Variable is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Variable is empty" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Variable is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Variable is not empty" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: IS_NUMERIC
# Checks if a variable is numeric
IS_NUMBER() {
    # check if is empty
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No variable provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No variable provided" >>"$DEBUG_LOG"
        return 1
    fi
    # Check if the variable is numeric
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: $1 is numeric"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1 is numeric" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: $1 is not numeric"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1 is not numeric" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: VAL_EMAIL
# Validates an email address
VAL_EMAIL() {
    # Check if the email address is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No email address provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No email address provided"
        return 1
    fi
    if [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Email address is valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Email address is valid" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Email address is not valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Email address is not valid" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: VAL_IP
# Validates an IP address
VAL_IP() {
    # Check if the IP address is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No IP address provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No IP address provided"
        return 1
    fi

    # Check if the IP address is valid
    if [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: IP address is valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: IP address is valid" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: IP address is not valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: IP address is not valid" >>"$DEBUG_LOG"
        return 1
    fi
}
# Function: VAL_IPV6
# Validates an IPv6 address
VAL_IPV6() {
    # Check if the IPv6 address is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No IPv6 address provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No IPv6 address provided"
        return 1
    fi

    # Check if the IPv6 address is valid
    if [[ "$1" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: IPv6 address is valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: IPv6 address is valid" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: IPv6 address is not valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: IPv6 address is not valid" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: VAL_URL
# Validates a URL
VAL_URL() {
    # Check if the URL is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No URL provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No URL provided"
        return 1
    fi

    # Check if the URL is valid
    if [[ "$1" =~ ^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: URL is valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: URL is valid" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: URL is not valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: URL is not valid" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: VAL_MACADDR
# Validates a MAC address
VAL_MACADDR() {
    # Check if the MAC address is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No MAC address provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No MAC address provided"
        return 1
    fi
    if [[ "$1" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: MAC address is valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: MAC address is valid" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: MAC address is not valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: MAC address is not valid" >>"$DEBUG_LOG"
        return 1
    fi
}

######################################################################
#                         5. File Management                         #
######################################################################
# Function: FILE_EXISTS
# Checks if a file exists
FILE_EXISTS() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        return 1
    fi
    if [[ -f "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 exists"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 exists" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 does not exist"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 does not exist" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: DIR_EXISTS
# Checks if a directory exists
DIR_EXISTS() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No directory provided"
        return 1
    fi

    if [[ -d "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Directory $1 exists"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Directory $1 exists" >>"$DEBUG_LOG"
        return 0
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO: Directory $1 does not exist"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Directory $1 does not exist" >>"$DEBUG_LOG"
    return 1

}

# Function: FILE_EMPTY
# Checks if a file is empty
FILE_EMPTY() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        return 1
    fi

    if [[ -s "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is not empty" >>"$DEBUG_LOG"
        return 1
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is empty" >>"$DEBUG_LOG"
        return 0
    fi
}

# Function: DIR_EMPTY
# Checks if a directory is empty
DIR_EMPTY() {
    #check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No directory provided"
        return 1
    fi

    if [[ "$(ls -A "$1")" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Directory $1 is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Directory $1 is not empty" >>"$DEBUG_LOG"
        return 1
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Directory $1 is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Directory $1 is empty" >>"$DEBUG_LOG"
        return 0
    fi
}

# Function: IS_WRITABLE
# Checks if a file or directory is writable
IS_WRITABLE() {
    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if the file or directory is writable
    if [[ -w "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is writable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is writable" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not writable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not writable" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: IS_READABLE
# Checks if a file or directory is readable
IS_READABLE() {
    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if the file or directory is readable
    if [[ -r "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is readable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is readable" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not readable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not readable" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: IS_EXECUTABLE
# Checks if a file or directory is executable
IS_EXECUTABLE() {
    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if the file or directory is executable
    if [[ -x "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is executable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is executable" >>"$DEBUG_LOG"
        return 0
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not executable"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not executable" >>"$DEBUG_LOG"
    return 1

}

# Function: IS_OWNED_BY_USER
# Checks if a file or directory is owned by the user
IS_OWNED_BY_USER() {
    # $1 = file or directory
    # $2 = user
    # return 0 = file or directory is owned by the user
    # return 1 = file or directory is not owned by the user
    # if $1 is empty, return 1
    # if $2 is empty, use $USER
    # if $2 is not empty, use $2

    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if argument $2 is empty
    if [[ -z "$2" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: No user provided, using $USER" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "INFO: No user provided, using $USER"
        USER="${USER}"
    else
        USER="$2"
    fi
    # check if the file or directory is owned by the user
    if [[ "$(stat -c "%U" "$1")" == "$USER" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is owned by the user"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is owned by the user $USER" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not owned by the user"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not owned by the user $USER" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: IS_OWNED_BY_GROUP
# Checks if a file or directory is owned by the group
IS_OWNED_BY_GROUP() {
    # $1 = file or directory
    # $2 = group
    # return 0 = file or directory is owned by the group
    # return 1 = file or directory is not owned by the group
    # if $1 is empty, return 1
    # if $2 is empty, use $USER
    # if $2 is not empty, use $2

    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if argument $2 is empty
    if [[ -z "$2" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: No group provided, using $USER" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "INFO: No group provided, using $USER"
        USER="$USER"
    else
        USER="$2"
    fi
    # check if the file or directory is owned by the group
    if [[ "$(stat -c "%G" "$1")" == "$USER" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is owned by the group $USER"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is owned by the group $USER" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not owned by the group"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not owned by the group $USER" >>"$DEBUG_LOG"
        return 1
    fi
}

# Function: IS_OLDER_THAN
# Checks if a file is older than X days
IS_OLDER_THAN() {
    # $1 = file
    # $2 = X days
    # return 0 = file is older than X days
    # return 1 = file is NOT older than X days
    # if $1 is empty, return 1
    # if $2 is empty, return 1
    # if $2 is not numeric, return 1

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        return 1
    fi
    if [[ -z "$2" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No days provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No days provided"
        return 1
    fi
    if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: X days is not numeric" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: X days is not numeric"
        return 1
    fi

    # check if the file is older than X days
    if [[ "$(find "$1" -mtime +"$2")" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is older than $2 days"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is older than $2 days" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is NOT older than $2 days"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is NOT older than $2 days" >>"$DEBUG_LOG"
        return 1
    fi
}

######################################################################
#                         6. Logging and Debugging                   #
######################################################################

# Function: LOG
# Log messages to /tmp/log/$SCRIPT.log
LOG() {
    # $1 = STATUS
    # $2 = MESSAGE
    # $3 = DEBUG_LOG
    # if $1 is empty, return 1
    # if $2 is empty, return 1
    # if $1 is not valid, set to INFO

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: LOG() no status provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: LOG() no message provided"
        return 1
    fi
    #check if $1 is INFO, WARNING, ERROR, DEBUG else add INFO to $1
    if ! [[ "$1" =~ ^(INFO|WARNING|ERROR|DEBUG)$ ]]; then
        STATUS="[INFO] : $1"
    else
        STATUS="$1"
        #if $2 provided then DEBUG_LOG=$2
        if [[ -z "$2" ]]; then
            DEBUG_LOG=$2
        fi
    fi

    MESSAGE="$2"
    #check if $3 is set then DEBUG_LOG=$3
    if [[ -n "$3" ]]; then
        DEBUG_LOG="$3"
    fi

    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') [$STATUS] : $MESSAGE" >>"$DEBUG_LOG"
    [[ "$VERBOSE" == "true" ]] && echo "[$STATUS] : $MESSAGE"

    return 0
}

######################################################################
#                         7. String Operations                      #
######################################################################

# Function: GENERATE_RANDOM
# Generate a random string
GENERATE_RANDOM() {
    # $1 = length
    # $2 = type
    # return = random string
    # if $1 is empty, return 1
    # if $2 is empty, return 1
    # if $2 is not valid, return 1
    # if $1 is not numeric, return 1

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM No length provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM No length provided"
        return 1
    fi
    if [[ -z "$2" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM No type provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM No type provided"
        return 1
    fi
    if ! [[ "$2" =~ ^[a-zA-Z]+$ ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM Invalid type" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM Invalid type"
        return 1
    fi
    if ! [[ "$1" =~ ^[0-9]+$ ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM Length is not numeric" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM Length is not numeric"
        return 1
    fi

    local LENGTH=$1
    local TYPE=$2
    local RESULT=""
    local CHARS

    case "$TYPE" in
    1 | "numbers")
        CHARS="0123456789"
        ;;
    2 | "characters")
        CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ;;
    3 | "mixed")
        CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        ;;
    *)
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: GENERATE_RANDOM Invalid type" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: GENERATE_RANDOM Invalid type"
        return 1
        ;;
    esac

    for ((i = 1; i <= LENGTH; i++)); do
        RESULT="${RESULT}${CHARS:RANDOM%${#CHARS}:1}"
    done

    echo "$RESULT"
}

# Function: STRING_LENGTH
# Count string length
STRING_LENGTH() {

    # $1 = string
    # return = string length
    # if $1 is empty, return 1
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No string provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No string provided"
        return 1
    fi
    local STRING_LENGTH
    STRING_LENGTH="${#1}"
    [[ "$VERBOSE" == "true" ]] && echo "INFO: String length is $STRING_LENGTH"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: String length is $STRING_LENGTH" >>"$DEBUG_LOG"

    echo "$STRING_LENGTH"
    return 0
}

######################################################################
#                         8. Network Operations                     #
######################################################################

# Function: GET_PUBLIC_IP
# Get public IP address
GET_PUBLIC_IP() {
    #check if curl or wget or python3 is installed
    #check if website returns a valid IP address else try another website
    #verbse and debug mode
    #return public IP address
    if ! command -v curl >/dev/null 2>&1; then
        if ! command -v wget >/dev/null 2>&1; then
            if ! command -v python3 >/dev/null 2>&1; then
                [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: curl or wget or python3 not installed" >>"$DEBUG_LOG"
                [[ "$VERBOSE" == "true" ]] && echo "ERROR: curl or wget or python3 not installed"
                return 1
            fi
        fi
    fi
    local PUBLIC_IP
    PUBLIC_IP=$(curl -s https://api.ipify.org) || PUBLIC_IP=$(wget -qO- https://api.ipify.org) || PUBLIC_IP=$(python3 -c 'import requests; print(requests.get("https://api.ipify.org").text')

    #check if public IP address is not valid then try another website
    if ! VAL_IP "$PUBLIC_IP"; then
        PUBLIC_IP=$(curl -s https://ifconfig.me) || PUBLIC_IP=$(wget -qO- https://ifconfig.me) || PUBLIC_IP=$(python3 -c 'import requests; print(requests.get("https://ifconfig.me").text')
    fi

    #check if public IP address is still not valid then try another website
    if ! VAL_IP "$PUBLIC_IP"; then
        PUBLIC_IP=$(curl -s https://ipecho.net/plain) || PUBLIC_IP=$(wget -qO- https://ipecho.net/plain) || PUBLIC_IP=$(python3 -c 'import requests; print(requests.get("https://ipecho.net/plain").text')
    fi

    echo "$PUBLIC_IP"
}

# Function: GET_LOCAL_IP
# Get local IP address
GET_LOCAL_IP() {
    if command -v ifconfig >/dev/null 2>&1; then
        # Try to get the IP address using ifconfig command
        local IP_ADDRESS
        IP_ADDRESS=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | head -n 1)
        if [[ "$IP_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$IP_ADDRESS"
            return 0
        fi
    fi

    # If neither command is available or both fail, log an error and return 1
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Unable to get local IP address" >>"$DEBUG_LOG"
    [[ "$VERBOSE" == "true" ]] && echo "ERROR: Unable to get local IP address"
    return 1
}

# Function: GET_MACADDR
# Get MAC address
GET_MACADDR() {
    #check if ip or ifconfig is installed
    #check if ip or ifconfig returns a valid MAC address
    #verbse and debug mode
    #return MAC address
    if ! command -v ip >/dev/null 2>&1; then
        if ! command -v ifconfig >/dev/null 2>&1; then
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: ip or ifconfig not installed" >>"$DEBUG_LOG"
            [[ "$VERBOSE" == "true" ]] && echo "ERROR: ip or ifconfig not installed"
            return 1
        fi
    fi
    local MACADDR
    MACADDR=$(ip link show | awk '/ether/ {print $2}') || MACADDR=$(ifconfig | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}')

    #check if MAC address is not valid then try another command
    if ! VAL_MACADDR "$MACADDR"; then
        MACADDR=$(ip link show | awk '/ether/ {print $2}') || MACADDR=$(ifconfig | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}')
    fi

    echo "$MACADDR"
}

# Function: CHECK_PERMISSIONS
CHECK_PERMISSIONS() {
    # Function: CHECK_PERMISSIONS
    # Description: Checks if a file/directory has specified permissions
    # Arguments:
    #   $1 - Path to file or directory
    #   $2 - Permission to check (octal or symbolic)
    # Returns:
    #   0 - Has permission
    #   1 - Does not have permission or error
    # Examples:
    #   CHECK_PERMISSIONS "/etc/passwd" "644"

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    if [[ -z "$2" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No permission provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No permission provided"
        return 1
    fi
    if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Permission is not numeric" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: Permission is not numeric"
        return 1
    fi

    # check if the file or directory has permission
    if [[ "$(stat -c "%a" "$1")" -ge "$2" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 has permission $2"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 has permission $2" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 does not have permission $2"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 does not have permission $2" >>"$DEBUG_LOG"
        return 1
    fi
}

######################################################################
#                         9. Testing Functions                       #
######################################################################

declare -g TOTAL_TESTS=0
declare -g PASSED_TESTS=0
declare -g FAILED_TESTS=0
declare -g DEBUG_LOG="/tmp/log/test_bashframe.log"

# Assert functions
ASSERT_TRUE() {
    local COMMAND="$1"
    local MESSAGE="$2"
    local ARGS="$3"

    ((TOTAL_TESTS += 1))
    if eval "$COMMAND" >/dev/null 2>&1; then
        echo -e "${GREEN}${BOLD}✓ PASS${NC}: $MESSAGE (${CYAN}'$ARGS'${NC}) ${GRAY}→${NC}"
        echo -e "  Expected: ${GREEN}${BOLD}TRUE${NC}"
        echo -e "  Got:      ${GREEN}${BOLD}TRUE${NC}"
        ((PASSED_TESTS += 1))
        return 0
    else
        echo -e "${RED}${BOLD}✗ FAIL${NC}: $MESSAGE (${CYAN}'$ARGS'${NC}) ${GRAY}→${NC}"
        echo -e "  Expected: ${GREEN}${BOLD}TRUE${NC}"
        echo -e "  Got:      ${RED}${BOLD}FALSE${NC}"
        ((FAILED_TESTS += 1))
        #return 1
        exit 1
    fi
}

ASSERT_FALSE() {
    local COMMAND="$1"
    local MESSAGE="$2"
    local ARGS="$3"

    let TOTAL_TESTS+=1

    if ! eval "$COMMAND" >/dev/null 2>&1; then
        echo -e "${GREEN}${BOLD}✓ PASS${NC}: $MESSAGE (${CYAN}'$ARGS'${NC}) ${GRAY}→${NC}"
        echo -e "  Expected: ${GREEN}${BOLD}FALSE${NC}"
        echo -e "  Got:      ${GREEN}${BOLD}FALSE${NC}"
        let PASSED_TESTS+=1
        return 0
    else
        echo -e "${RED}${BOLD}✗ FAIL${NC}: $MESSAGE (${CYAN}'$ARGS'${NC}) ${GRAY}→${NC}"
        echo -e "  Expected: ${GREEN}${BOLD}FALSE${NC}"
        echo -e "  Got:      ${RED}${BOLD}TRUE${NC}"
        let FAILED_TESTS+=1
        #return 1
        exit 1
    fi
}

ASSERT_EQUALS() {
    local EXPECTED="$1"
    local ACTUAL="$2"
    local MESSAGE="$3"

    let TOTAL_TESTS+=1

    if [ "$EXPECTED" = "$ACTUAL" ]; then
        echo -e "${GREEN}${BOLD}✓ PASS${NC}: $MESSAGE ${GRAY}→${NC}"
        echo -e "  Expected: ${GREEN}${BOLD}'$EXPECTED'${NC}"
        echo -e "  Got:      ${GREEN}${BOLD}'$ACTUAL'${NC}"
        let PASSED_TESTS+=1
        return 0
    else
        echo -e "${RED}${BOLD}✗ FAIL${NC}: $MESSAGE ${GRAY}→${NC}"
        echo -e "  Expected: ${GREEN}${BOLD}'$EXPECTED'${NC}"
        echo -e "  Got:      ${BLUE}${BOLD}'$ACTUAL'${NC}"
        let FAILED_TESTS+=1
        return 1
    fi
}
