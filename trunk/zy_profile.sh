# add syntax highlight for LESS
export LESS=" -R "
export HISTCONTROL=ignorespace


# add cmd tracking
declare -r REAL_LOGNAME=`/usr/bin/who am i | cut -d" " -f1`
if [ $USER == root ]; then
        declare -r PROMT="#"
else
        declare -r PROMT="$"
fi

if [ x"$ZY_USER" == x ]; then
        declare -r REMOTE_USER=UNKNOW
else
        declare -r REMOTE_USER=$ZY_USER
fi

PPPID=$(pstree -p | grep $$ | sed 's/.*sshd(//g; s/).*//g')

declare -r h2l='
    THIS_HISTORY="$(history 1)"
    __THIS_COMMAND="${THIS_HISTORY/*:[0-9][0-9] /}"
    if [ x"$LAST_HISTORY" != x"$THIS_HISTORY" ];then
        if [ x"$__LAST_COMMAND" != x ]; then
        __LAST_COMMAND="$__THIS_COMMAND"
        LAST_HISTORY="$THIS_HISTORY"
        logger -p local4.notice -t $REAL_LOGNAME "PPPID=$PPPID [$USER@$HOSTNAME $PWD]$PROMT $__LAST_COMMAND"
    else
            __LAST_COMMAND="$__THIS_COMMAND"
            LAST_HISTORY="$THIS_HISTORY"
    fi
    fi'
trap "$h2l" DEBUG
