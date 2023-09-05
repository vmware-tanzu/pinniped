#!/usr/bin/env bash

# https://gist.github.com/mohanpedala/1e2ff5661761d3abd0385e8223e16425
set -e # immediately exit
set -u # error if variables undefined
set -o pipefail # prevent masking errors in a pipeline
# set -x # print all executed commands to terminal


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'

echo_yellow() {
    echo -e "${YELLOW}>> $@${DEFAULT}\n"
    # printf "${GREEN}$@${DEFAULT}"
}

echo_green() {
    echo -e "${GREEN}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_red() {
    echo -e "${RED}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_blue() {
    echo -e "${BLUE}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
