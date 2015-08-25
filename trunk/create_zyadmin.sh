#!/bin/bash

MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \
abcdefghijklmnopqrstuvwxyz./*&^%$#@!()"
# May change 'LENGTH' for longer password, of course.
LENGTH="8"

while [ "${n:=1}" -le "$LENGTH" ]; do
    PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
    let n+=1
done

#echo "$PASS" # ==> Or, redirect to file, as desired.
#exit 0

create_user(){
cat /etc/passwd | grep zyadmin > /dev/null
if [ $? -eq 0 ]
then echo "User exist"; exit 1
fi
cat /etc/group | grep sshers > /dev/null
if [ $? -ne 0 ]
then echo "SSH group doesn't exit"; exit 1
fi
useradd -G sshers zyadmin
echo "$PASS" | passwd zyadmin --stdin
}

setup_sudo(){
grep zyadmin /etc/sudoers
if [ $? -eq 0 ]
then echo "User already in sudo"; exit 1
fi
  echo '
zyadmin        ALL=(ALL)       NOPASSWD: ALL
Defaults:zyadmin   !requiretty
' >>/etc/sudoers

}

send_passwd(){
### Binary Definition ###
MAIL=/bin/mail
EMAIL_ADDRESS1=86884529@qq.com
EMAIL_ADDRESS2=
EMAIL_ADDRESS3=
EMAIL_ADDRESS4=
EMAIL_ADDRESS5=
EMAIL_ADDRESS6=

DATE=$(date "+%Y%m%d")
PASS_FILE=/tmp/pass_temp
echo "$PASS" > $PASS_FILE
HOSTNAME=$(hostname)

# Send email
echo "Please check the attached" | $MAIL -s "Password Report on $HOSTNAME - $DATE " $EMAIL_ADDRESS1 -c $EMAIL_ADDRESS2,$EMAIL_ADDRESS5,$EMAIL_ADDRESS6 < $PASS_FILE
rm -rf $PASS_FILE
exit 0
}
create_user
setup_sudo
send_passwd
