cd /opt
wget http://zy-res.oss-cn-hangzhou.aliyuncs.com/server/zabbix-2.2.3.tar.gz -O zabbix-2.2.3.tar.gz
tar xzf zabbix-2.2.3.tar.gz
cd zabbix-2.2.3
prefix="/usr/local/zabbix-agent"
./configure --enable-agent  --prefix=${prefix}
make -j 2
make install
groupadd zabbix
useradd -g zabbix zabbix
#sed -i "s/Server=127.0.0.1/Server=114.215.177.175/" /usr/local/zabbix/etc/zabbix_agentd.conf
#sed -i "s/Hostname=Zabbix server//" /usr/local/zabbix/etc/zabbix_agentd.conf
#echo "ListenPort=30005" >> /usr/local/zabbix/etc/zabbix_agentd.conf
mv ${prefix}/etc/zabbix_agentd.conf ${prefix}/etc/zabbix_agentd.conf-old
echo "LogFile=/tmp/zabbix_agentd.log
DebugLevel=3
Server=zabbix.jiagouyun.com
#ServerActive=zabbix.jiagouyun.com
Hostname= 
Include=${prefix}/etc/zabbix_agentd.conf.d/">${prefix}/etc/zabbix_agentd.conf
${prefix}/sbin/zabbix_agentd
echo "please add the hostname in the zabbix_agentd.conf"
