export LOGNAME=$(cat /tmp/mcd-setup.user)
. /home/$LOGNAME/.bashrc
export PS1="# "
export MCD_SOCK=/tmp/mcd.sock
unset PROMPT_COMMAND
