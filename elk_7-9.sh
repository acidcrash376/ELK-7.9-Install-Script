#!/bin/bash
# ------------------------------------------------------------------
# [Author     ] acidcrash376
# [Title      ] ELK (v7.9) stack install script
# [Description] Script to install Elasticearch, Logstash and Kibana		
# [Created    ] 06/09/2020
# [Last Update] 06/09/2020
# [Version    ] v1.0
# [URL        ] https://github.com/acidcrash376/ELK-7.9-Install-Script
# ------------------------------------------------------------------
ip=$(hostname -I)
ip=`echo $ip | sed 's/ *$//g'`
elasticpath='/etc/elasticsearch/*'
kibanapath='/etc/kibana/*'
logstashpath='/etc/logstash/*'
nginxpath='/etc/nginx/*'

function initialCheckSvc()
{
echo -e "\e[33m [-] Checking ${1} service is running\e[0m"
ps auxw | grep -v grep | grep -w $1 > /dev/null
if [ $? != 0 ]
then
	systemctl start elasticsearch.service;
	sleep 2
	checkSvc $1
else
	echo -e "\e[32m [\xE2\x9c\x94] "$1" is running";
fi;
}

function checkSvc()
{
ps auxw | grep -v grep | grep -w $1 > /dev/null
if [ $? != 0 ]
then
	systemctl start $1
	initialCheckSvc $1;
else
	echo -e "\e[32m [\xE2\x9c\x94] "$1" is running";
fi;
}

function checkPort()
{
echo -e "\e[33m [-] Checking port ${1} is listening\e[0m"
vara=$(ss -tulnw | grep ${1} | cut -d":" -f1 | awk '{ print $5}')
while ! ss -tulnw | grep [0-9]:${1} -q; do
	sleep 5
done
vara=$(ss -tulnw | grep ${1} | cut -d":" -f1 | awk '{ print $5}')
echo -e "\e[32m [\xE2\x9c\x94] "$vara "is listening on "$1 "\e[0m";
}

function getreq {
dpkg -s $1 &> /dev/null
if [ $? -ne 0 ]
	then
        #echo -e "\e[33m" $tool "is not installed, installing...\e[0m"
        #echo " "
        apt update &> /dev/null
        apt install $1 -y &> /dev/null
        echo -e "\e[32m [\xE2\x9C\x94]" $1 "has been installed\e[0m"
        #echo " "
    else
        echo -e "\e[32m [\xE2\x9C\x94]"  $1 "is already installed\e[0m"
	#echo " "
fi
}

function checkpriv {
if [ "$EUID" -ne 0 ]
  	then
		echo -e "\e[31m        Please run as root! Exiting...\e[39m"
  		exit
fi
}

echo -e "\e[36m +--------------------------------------+"
echo -e "\e[36m | $(date)         |"
echo -e "\e[36m | Starting ELK Install Script          |"
echo -e "\e[36m | ELK Stack for Debian based systems   |"
echo -e "\e[36m |\e[1m E\e[22mlastic - \e[1mL\e[22mogstash - \e[1mK\e[22mibana          |"
echo -e "\e[36m | nginx reverse proxy                  |"
echo -e "\e[36m +--------------------------------------+"
echo ""
echo -e " \e[1;4;34mELK Installer Status\e[0m"
echo ""

checkpriv
#echo -e "\e[33m [-] System Update...\e[0m"
#apt update &> /dev/null
#apt upgrade -y &> /dev/null
#echo -e "\e[32m [\xE2\x9C\x94] System Update - Complete\e[0m"
echo -e "\e[33m [!] Adding the elasticsearch repo \e[0m"
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - &> /dev/null
echo -e "\e[32m [\xE2\x9C\x94] elastic Gnu Privacy Guard key added successfully \e[0m"

apt install apt-transport-https -y &> /dev/null
echo -e "\e[32m [\xE2\x9C\x94] apt-transport-https successfully \e[0m"

echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list
echo -e "\e[32m [\xE2\x9C\x94] elastic Repo added to source list successfully \e[0m"

apt update &> /dev/null
echo -e "\e[32m [\xE2\x9C\x94] apt repo list updated\e[0m"



echo -e "\e[33m [!] Installing pre-requisites, this can take a few minutes \e[0m"
getreq "curl"
#getreq "openssh-server"
getreq "elasticsearch"
getreq "kibana"
getreq "openjdk-14-jre"
getreq "logstash"
getreq "apache2-utils"
getreq "nginx"

read -p "Press any key to resume..."

## Config Stage ##

#######################
# elasticsearch       #
#######################
echo -e "\e[33m [!] Configuring elasticstack\e[0m"
tar -czvf /etc/elasticsearch/elasticsearch_$(date +'%F_%H-%M-%S').tar.gz ${elasticpath} &> /dev/null
cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.original
sed -i 's/-Xms1g/-Xms3g/g' /etc/elasticsearch/jvm.options
sed -i 's/-Xmx1g/-Xmx3g/g' /etc/elasticsearch/jvm.options
echo -e "\e[32m [\xE2\x9c\x94] elasticsearch JVM heapsize set to 3GB. This should be aproximately half of the system memory available.\e[0m"

echo -e "\e[33m [-] elasticsearch.yml\e[0m"
sleep 0.5
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.original
sed -i "s/#node.name: node-1/node.name: ${HOSTNAME}/g" /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] node.name changed to ${HOSTNAME}\e[0m"
sed -i 's/#network.host: 192.168.0.1/network.host: 127.0.0.1/g' /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] network.host changed to 127.0.0.1\e[0m"
sed -i "/network.host: 127.0.0.1/a http.host: ${ip}" /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] http.host: ${ip} added so will listen on any IP\e[0m"
sed -i 's/#http.port: 9200/http.port: 9200/g' /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] http.port set to 9200\e[0m"
sed -i 's/#bootstrap.memory_lock: true/bootstrap.memory_lock: true/g' /etc/elasticsearch/elasticsearch.yml
echo -e "\e[32m --> [\xE2\x9c\x94] bootstrap.memory_lock enabled, defining heap size\e[0m"

#sed -i "s/#discovery.seed_hosts: \[\"host1\", \"host2\"]/discovery.seed_hosts: ["${ip}", "127.0.0.1"]/g" /etc/elasticsearch/elasticsearch.yml
#echo -e "\e[32m --> [\xE2\x9c\x94] discovery.seed_hosts changed to ${ip}\e[0m"
#sed -i "s/#cluster.initial_master_nodes: \[\"node-1\", \"node-2\"]/cluster.initial_master_nodes: \['${ip}']/g" /etc/elasticsearch/elasticsearch.yml
#echo -e "\e[32m --> [\xE2\x9c\x94] cluster.initial_master_nodes changed to ${ip}\e[0m"
echo -e "\e[32m [\xE2\x9c\x94] elasticsearch YAML config file updated\e[0m"

systemctl enable elasticsearch.service &> /dev/null
initialCheckSvc "elasticsearch" ${ip}
checkPort "9200" ${ip}

read -p "Press any key to resume..."


#######################
# kibana              #
#######################
echo -e "\e[33m [-] kibana.yml\e[0m"
tar -czvf kibana_$(date +'%F_%H-%M-%S').tar.gz * &> /dev/null
cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.original
sed -i "s/#server.host: \"localhost\"/server.host: \"${ip}\"/g" /etc/kibana/kibana.yml
echo -e "\e[32m --> [\xE2\x9c\x94] server.host set to ${ip} \e[0m"
sed -i "s/#elasticsearch.hosts: \[\"http:\/\/localhost:9200\"]/elasticsearch.hosts: \[\"http:\/\/${ip}:9200\"]/g" /etc/kibana/kibana.yml
echo -e "\e[32m --> [\xE2\x9c\x94] elasticsearch.hosts changed to http://localhost:9200\e[0m"
sed -i 's/#logging.dest: stdout/logging.dest: \/var\/log\/kibana.log/g' /etc/kibana/kibana.yml
echo -e "\e[32m --> [\xE2\x9c\x94] logging.dest changed to /var/log/kibana.log\e[0m"
echo -e "\e[32m [\xE2\x9c\x94] kibana YAML config file updated\e[0m"

touch /var/log/kibana.log
chown kibana:kibana /var/log/kibana.log
chmod u+w /var/log/kibana.log
echo -e "\e[32m [\xE2\x9c\x94] kibana log file created\e[0m"

systemctl enable kibana.service &> /dev/null
initialCheckSvc "kibana" ${ip}
checkPort "5601" ${ip}

read -p "Press any key to resume..."

#######################
# logstash            #
#######################
echo -e "\e[33m [-] logstash.yml\e[0m"
tar -czvf logstash_$(date +'%F_%H-%M-%S').tar.gz * &> /dev/null
cp /etc/logstash/logstash.yml /etc/logstash/logstash.yml.original
sed -i "s/# node.name: test/node.name: ${HOSTNAME}/g" /etc/logstash/logstash.yml
echo -e "\e[32m --> [\xE2\x9c\x94] node.name changed to ${HOSTNAME}\e[0m"
sed -i "s/# http.host: 127.0.0.1/http.host: ${ip}/g" /etc/logstash/logstash.yml
echo -e "\e[32m --> [\xE2\x9c\x94] http.host changed to ${ip}\e[0m"
touch /etc/logstash/conf.d/auditbeat.conf
#echo "## INPUTS SECTION
#input {
#	beats {
#		ports => 5044
#	}
#}
## OUTPUTS SECTION
#output {
#	elasticsearch {
#		hosts => ["http://${ip}:9200"]
#		index => "%{[@metadata][beat]-%{-YYYY.MM.dd}"
##	}
#}" > /etc/logstash/conf.d/auditbeat.conf

echo "input {
  beats {
    host => \"${ip}\"
    port => 5044
  }
}" > /etc/logstash/conf.d/02-beats-input.conf 

echo "output {
  if [@metadata][pipeline] {
    elasticsearch {
    hosts => [\"${ip}:9200\"]
    manage_template => false
    index => \"%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}\"
    pipeline => \"%{[@metadata][pipeline]}\"
    }
  } else {
    elasticsearch {
    hosts => [\"${ip}:9200\"]
    manage_template => false
    index => \"%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}\"
    }
  }
}" > /etc/logstash/conf.d/30-elasticsearch-output.conf 

systemctl enable logstash.service &> /dev/null
initialCheckSvc "logstash" ${ip}
checkPort "5044" ${ip}

read -p "Press any key to resume..."

#######################
# nginx reverse proxy #
#######################
tar -czvf nginx_$(date +'%F_%H-%M-%S').tar.gz * &> /dev/null
mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.original
touch /etc/nginx/sites-available/default
systemctl stop nginx
echo "server {
        listen ${ip}:80;
        server_name elk.test;
        auth_basic \"Restricted Access\";
        auth_basic_user_file /etc/nginx/htpasswd.kibana;

        location / {
                proxy_pass http://${ip}:5601;
                proxy_http_version 1.1;
                proxy_set_header upgrade \$http_upgrade;
                proxy_set_header connection 'upgrade';
                proxy_set_header host \$host;
                proxy_cache_bypass \$http_upgrade;
        }
}
" > /etc/nginx/sites-available/default
diff /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default &>/dev/null
if [ $? -eq 1 ]
then
	echo "sites-available and sites-enabled default files do not match"
	rm -f /etc/nginx/sites-enabled/default
	ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
	echo -e "\e[32m --> [\xE2\x9c\x94] nginx default site configured as a reverse proxy\e[0m"
else
	echo -e "\e[32m --> [\xE2\x9c\x94] nginx default site configured as a reverse proxy\e[0m"
fi
nginx -t &>/dev/null
if [ $? -eq 1 ]
then 
	echo -e "\e[32m [\e[31m\xE2\x9c\x97\e[32m] Something broke in nginx's config...\e[0m"
else
	echo -e "\e[32m --> [\xE2\x9c\x94] nginx config is ok\e[0m"
fi
echo "Pa55w0rd=01" | htpasswd -b -i -B -c /etc/nginx/htpasswd.kibana cpt-admin > /dev/null
echo -e "\e[32m --> [\xE2\x9c\x94] default user of cpt-admin with default password of Pa55w0rd=01 has been created\e[0m"
echo -e "\e[33m --> [!] Please change this after the script finishes. \n --> [!] 'echo \"NewPasswordHere\" | htpasswd -b -i -B /etc/nginx/htpasswd.kibana cpt-admin' \n --> [!] You can add additional users using the same command one-liner \e[0m"

systemctl enable nginx.service &> /dev/null
initialCheckSvc "nginx" ${ip}
checkPort "80" ${ip}


echo -e "\e[32m Elastic, Logstash and Kibana with an nginx reverse proxy has been installed, \nyou can reach the kibana dashboard via http://${ip} or a hostname if you have defined one. \nYou now need to configure your agents...\e[0m"
