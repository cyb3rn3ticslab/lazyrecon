#!/bin/bash

# Use colors, but only if connected to a terminal, and that terminal
# supports them.
if [ -t 1 ]; then
  RB_RED=$(printf '\033[38;5;196m')
  RB_ORANGE=$(printf '\033[38;5;202m')
  RB_YELLOW=$(printf '\033[38;5;226m')
  RB_GREEN=$(printf '\033[38;5;082m')
  RB_BLUE=$(printf '\033[38;5;021m')
  RB_INDIGO=$(printf '\033[38;5;093m')
  RB_VIOLET=$(printf '\033[38;5;163m')
  RB_GRAY=$(printf '\033[4;49;90m')

  RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m')
  YELLOW=$(printf '\033[33m')
  BLUE=$(printf '\033[34m')
  BOLD=$(printf '\033[1m')
  RESET=$(printf '\033[m')
else
  RB_RED=""
  RB_ORANGE=""
  RB_YELLOW=""
  RB_GREEN=""
  RB_BLUE=""
  RB_INDIGO=""
  RB_VIOLET=""

  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  BOLD=""
  RESET=""
fi


echo "${BLUE}reconnaissance starting up!"
printf '  %s _%s        %s    %s      %s     %s   %s     %s     %s \n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
printf '  %s| |%s __ _ %s____%s _   _ %s_ __ %s___%s  ___ %s ___%s  _ __%s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
printf '  %s| |%s/ _  |%s_  /%s| | | %s|  __%s/ _ \%s/ __|%s/ _ \%s|  _ \ %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
printf '  %s| |%s (_|  %s/ / %s| | | %s| | %s|  __/%s (__ %s (_) %s| | | %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
printf '  %s|_|%s\__ _|%s___/%s \__  %s|_ %s  \___|%s\___|%s\___/%s|_| |_%sv2%s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_VIOLET $RB_GRAY  $RESET
printf '  %s   %s      %s    %s |___/%s    %s       %s     %s     %s       %s\n' $RB_RED $RB_ORANGE $RB_YELLOW $RB_GREEN $RB_RED $RB_BLUE $RB_INDIGO $RB_VIOLET $RB_RESET
printf "\n"
echo "${BLUE}nahamsec/lazyrecon v1.0 forked by storenth/lazyrecon v2.0"
echo "${BLUE}${BOLD}To keep up on the latest news and updates, follow me on Twitter: https://twitter.com/storenth"
printf "${BLUE}${BOLD}%s${RESET}\n" "I am looking for your support: https://github.com/storenth/lazyrecon"
printf "\n"
exit 0
