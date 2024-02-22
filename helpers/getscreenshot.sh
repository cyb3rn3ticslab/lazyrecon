#!/bin/bash

# https://bugs.chromium.org/p/chromium/issues/detail?id=1097565&can=2&q=component%3AInternals%3EHeadless

# get page and take screenshot
# https://developers.google.com/web/updates/2017/04/headless-chrome#screenshots

# SCOPE=$(echo $2 | awk -F '//' '{print $NF}')
SCOPE=$(echo $2 | grep -oriahE "(([[:alpha:][:digit:]-]+\.)+)?[[:alpha:][:digit:]-]+\.[[:alpha:]]{2,5}([:][[:digit:]]{2,4})?" | sed "s/:/_/;s/[.]/_/g")
chromium --headless --disable-gpu --no-sandbox --window-size=1280,720 --screenshot="${1}/${SCOPE}.png" $2
