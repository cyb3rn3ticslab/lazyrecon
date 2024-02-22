#! /bin/bash
#
# Perform alteration on digits

# definitions
checkhelp(){
  echo "./alterate.sh enumerated-list.txt"
  exit 0
}

if [ $# -eq 0 ]; then
  checkhelp "$@"
fi


#######################################
# grep one digit to alterate
# Arguments:
#   file
# Example:
#   test.1.demo.com -->
#   test.2.demo.com
#   test.3.demo.com
#   ...
#######################################
onedigit(){
  ONEDIGIT=$(grep -E "[-][[:digit:]][-]" $1)
  if [[ -n $ONEDIGIT ]]; then
    for X in {0..102}; do
      echo "$ONEDIGIT" | sed -E "s/[-][[:digit:]][-]/-${X}-/"
    done
  fi

  ONEDIGIT_2=$(grep -E "[.][[:digit:]][.]" $1)
  if [[ -n $ONEDIGIT_2 ]]; then
    for X in {0..102}; do
      echo "$ONEDIGIT_2" | sed -E "s/[.][[:digit:]][.]/.${X}./"
    done
  fi

  ONEDIGIT_3=$(grep -E "[.][[:digit:]][-]" $1)
  if [[ -n $ONEDIGIT_3 ]]; then
    for X in {0..102}; do
      echo "$ONEDIGIT_3" | sed -E "s/[.][[:digit:]][-]/.${X}-/"
    done
  fi

  ONEDIGIT_4=$(grep -E "[-][[:digit:]][.]" $1)
  if [[ -n $ONEDIGIT_4 ]]; then
    for X in {0..102}; do
      echo "$ONEDIGIT_4" | sed -E "s/[-][[:digit:]][.]/-${X}./"
    done
  fi

  ONEDIGIT_5=$(grep -vE -e "[._-][[:digit:]][._-]" -e "[._-][[:digit:]]{2}[._-]" -e "([._-]|[[:alpha:]])[[:digit:]]{2}([._-])|[[:alpha:]])" $1 | grep -E "([._-]|[[:alpha:]])[[:digit:]]([._-]|[[:alpha:]])")
  if [[ -n $ONEDIGIT_5 ]]; then
    for X in {0..102}; do
      echo "$ONEDIGIT_5" | sed -E "s/[[:digit:]]/${X}/"
    done
  fi
}

#######################################
# grep two digits to alterate
# Arguments:
#   file
# Example:
#   test.28.demo.com -->
#   test.1.demo.com
#   ...
#   test.102.demo.com
#######################################
twodigit() {
  TWODIGIT_1=$(grep -E "[-][[:digit:]]{2}[-]" $1)
  if [[ -n $TWODIGIT_1 ]]; then
    for X in {0..102}; do
      echo "$TWODIGIT_1" | sed -E "s/[-][[:digit:]]{2}[-]/-${X}-/"
    done
  fi

  TWODIGIT_2=$(grep -E "[.][[:digit:]]{2}[.]" $1)
  if [[ -n $TWODIGIT_2 ]]; then
    for X in {0..102}; do
      echo "$TWODIGIT_2" | sed -E "s/[.][[:digit:]]{2}[.]/.${X}./"
    done
  fi

  TWODIGIT_3=$(grep -E "[-][[:digit:]]{2}[.]" $1)
  if [[ -n $TWODIGIT_3 ]]; then
    for X in {0..102}; do
      echo "$TWODIGIT_3" | sed -E "s/[-][[:digit:]]{2}[.]/-${X}./"
    done
  fi

  TWODIGIT_4=$(grep -E "[.][[:digit:]]{2}[-]" $1)
  if [[ -n $TWODIGIT_4 ]]; then
    for X in {0..102}; do
      echo "$TWODIGIT_4" | sed -E "s/[.][[:digit:]]{2}[-]/.${X}-/"
    done
  fi

  TWODIGIT_5=$(grep -vE -e "[._-][[:digit:]][._-]" -e "[._-][[:digit:]]{2}[._-]" $1 | grep -E "([._-]|[[:alpha:]])[[:digit:]]{2}([._-]|[[:alpha:]])")
  if [[ -n $TWODIGIT_5 ]]; then
    for X in {0..102}; do
      echo "$TWODIGIT_5" | sed -E "s/[[:digit:]]{2}/${X}/"
    done
  fi
}

#######################################
# grep three and more digits to alterate
# Arguments:
#   file
# Example:
#   test.957.demo.com -->
#   test.1.demo.com
#   ...
#   test.99999.demo.com
#######################################
threeandmoredigits() {
  THREEANDMORE_1=$(grep -E '[[:digit:]]{3,}' $1)
  if [[ -n $THREEANDMORE_1 ]]; then
    for X in {0..99999}; do
      echo "$THREEANDMORE_1" | sed -E "s/[[:digit:]]{3,}/${X}/"
    done
  fi
}


# main entry point
onedigit "$1"
twodigit "$1"
threeandmoredigits "$1"
