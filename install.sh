#! /bin/bash
# global variables
export http_proxy="|HTTPPROXY|";
export install_log="/tmp/lab-install.log";
export _sites_enabled="/etc/apache2/sites-enabled";
export _sites_available="/etc/apache2/sites-available";
export _mods_enabled="/etc/apache2/mods-enabled";
export _mods_available="/etc/apache2/mods-available";

# sudo install apt packages via proxy
function aptInstall() {
  sudo http_proxy=${http_proxy} apt install ${1} -y || return 1;
  return 0;
}

# setup the initial docker instance
function setupSparkContainer() {
  echo "Running ${FUNCNAME[0]}";
  # install docker and docker compose
  echo "Installing Docker dependencies";
  aptInstall docker.io &>/dev/null || return 1;
  aptInstall docker-compose &>/dev/null || return 1;

  # enable docker pull per template
  echo "Enabling docker with proxy settings";
  sudo mkdir -p /etc/systemd/system/docker.service.d;
  sudo cat << EOF >> /etc/systemd/system/docker.service.d/proxy.conf
[Service]
Environment="HTTP_PROXY=${http_proxy}"
Environment="HTTPS_PROXY=${http_proxy}"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
EOF
  sudo systemctl daemon-reload &>/dev/null;
  sudo systemctl restart docker &>/dev/null;
  # docker can now pull

  # create directory to run spark from
  echo "Creating Spark install directory";
  sudo mkdir /opt/spark &>/dev/null;
  local current_dir=$PWD;

  # create docker compose file using vulnerable spark version 3.1.1 from bitnami
  # port 80 is mapped to internal docker port 8080 running spark
  # port 443 is used in the final exercise for a bind-shell
  echo "Creating Docker compose file for Spark v3.1.1 mapped to TCP 127.0.0.1:8080 -> 8080";
  sudo cat << EOF > /opt/spark/docker-compose.yml
version: '2'
services:
  spark:
    image: docker.io/bitnami/spark:3.1.1
    environment:
      - SPARK_MODE=master
      - SPARK_RPC_AUTHENTICATION_ENABLED=no
      - SPARK_RPC_ENCRYPTION_ENABLED=no
      - SPARK_LOCAL_STORAGE_ENCRYPTION_ENABLED=no
      - SPARK_SSL_ENABLED=no
    ports:
      - '127.0.0.1:8080:8080'
      - '443:443'
EOF

  # create vulnerable acl configuration file
  echo "Creating vulnerable Spark ACL configuration";
  sudo cat << EOF > /opt/spark/spark-defaults.conf
spark.acls.enable true
EOF

  # spin up docker instance
  echo "Initializing Spark instance";
  cd /opt/spark && sudo screen -dm -S spark-compose -s /bin/bash docker-compose up;

  # initialize docker to copy vulnerable config
  echo "Waiting for Docker to finish initializing (this may take a minute)";
  while true; do
    if (sudo docker exec -it spark_spark_1 cat /opt/bitnami/spark/conf/spark-defaults.conf &>/dev/null); then
      # copy the configuration file
      printf "\nCopying the vulnerable Spark configuration to the Docker instance\n";
      sudo docker cp spark-defaults.conf spark_spark_1:/opt/bitnami/spark/conf/spark-defaults.conf
      # verify the contents before exiting
      printf "Verifying configuration copied to Docker instance\n";
      sudo docker exec -it spark_spark_1 cat /opt/bitnami/spark/conf/spark-defaults.conf|
        grep -ia 'spark.acls.enable true' && break;
    fi;
    printf ".";
    # echo "Still waiting for Docker to finish initializing";
    sleep 0.5s;
  done;

  # send graceful shutdown ^C to restart the screen session
  printf "\nSending graceful shutdown to the Spark instance\n";
  sudo screen -S spark-compose -p 0 -X stuff $'\003';

  echo "Waiting for the Docker instance to terminate (this may take a minute)";
  while true; do
    (sudo screen -ls spark-compose|grep -ia "spark-compose" &>/dev/null) || break;
    printf ".";
    # echo "Still waiting for the Docker instance to terminate";
    sleep 0.5s;
  done;

  # spin up docker instance with vulnerable configuration
  printf "\nRestarting the Spark instance with the vulnerable configuration\n";
  sudo screen -dm -S spark-compose -s /bin/bash docker-compose up;
  cd ${current_dir};
  echo "${FUNCNAME[0]} complete";
  return 0;
}

# setup apache as reverse proxy
function setupApacheProxy() {
  echo "Running ${FUNCNAME[0]}";
  echo "Installing Apache dependencies";
  aptInstall apache2 &>/dev/null || return 1;
  aptInstall libapache2-mod-security2 &>/dev/null || return 1;
  sudo systemctl stop apache2 &>/dev/null;

  echo "Backing up original Apache configuration files";
  for _file in "apache2.conf" "ports.conf"; do
    sudo cp "/etc/apache2/${_file}" "/etc/apache2/${_file}.orig";
  done;

  echo "Creating ports.conf configuration file for HTTP only";
  sudo cat << EOF > /etc/apache2/ports.conf
Listen 0.0.0.0:80
EOF

  echo "Creating apache2.conf configuration file";
  sudo cat << EOF > /etc/apache2/apache2.conf
# DEFAULT VALUES
DefaultRuntimeDir \${APACHE_RUN_DIR}
PidFile \${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
HostnameLookups Off
# PROCESS CONTEXT
User \${APACHE_RUN_USER}
Group \${APACHE_RUN_GROUP}
# ERROR LOG LOCATION AND LEVEL
ErrorLog \${APACHE_LOG_DIR}/error.log
LogLevel warn
# MODULES INCLUDED
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
# VIRTUAL HOST SETTINGS
Include ports.conf
<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>
<Directory /usr/share>
	AllowOverride None
	Require all granted
</Directory>
<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>
AccessFileName .htaccess
<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>
# LOG FORMAT SETTINGS
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
# INCLUDE CONFIGURATION AND SITE FILES
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
EOF

  echo "Creating apache-www.conf configuration file and symlink";
  sudo cat << EOF > ${_sites_available}/apache-www.conf
<VirtualHost 0.0.0.0:80>
    # HOST SPECIFIC ENTRIES
    Define SERVER_ADMIN admin
    Define SERVER_NAME $(hostname)
    Define DOCUMENT_ROOT /var/www/html/
    Define APACHE_LOG_DIR /var/log/apache2/
    # DEFAULT ENTRIES
    ServerAdmin \${SERVER_ADMIN}@\${SERVER_NAME}
    # forensic log for enhanced logging
    #DETECT ForensicLog \${APACHE_LOG_DIR}/forensic.log
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
    ServerName \${SERVER_NAME}
    DocumentRoot \${DOCUMENT_ROOT}
    # MODULES
    RewriteEngine On
    SSLProxyEngine On
    SSLEngine off
    #DETECT SecRuleEngine On
    # MODULE SETTINGS
    SSLProxyCheckPeerCN Off
    SSLProxyVerify none
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off
    # SECURITY RULES
    # detect the bash string in the doAs query parameter
    #DETECT SecRule ARGS:doAs "@contains bash" "id:254,log,pass,status:403,msg:'CVE-2022-33891 - doAs contains bash'"
    #PREVENT SecRule ARGS:doAs "@rx (.*)" "id:255,deny,status:403,msg:'CVE-2022-33891 - doAs blocked'"
    # REWRITE RULES
    # redirect to local spark instance if doAs in query string
    #EXTRA RewriteCond %{QUERY_STRING} ^doAs=(.*)
    #EXTRA RewriteRule ^(.*) http://127.0.0.1:8081/\$1 [NC,L,P]
    # redirect to local spark instance
    RewriteRule ^(.*) http://127.0.0.1:8080/\$1 [NC,L,P]
</VirtualHost>
EOF
  for _conf in $(find ${_sites_enabled}/*conf); do
    sudo unlink ${_conf} &>/dev/null;
  done;
  sudo ln -s ${_sites_available}/apache-www.conf ${_sites_enabled}/apache-www.conf;

  echo "Enabling Apache modules";
  sudo a2enmod ssl &>/dev/null;
  sudo a2enmod proxy rewrite &>/dev/null;
  sudo a2enmod proxy proxy_http &>/dev/null;

  # setup apache mod-security
  echo "Configuring ModSecurity for detection only";
  sudo cat << EOF > /etc/modsecurity/modsecurity.conf
# RULE ENGINE INITIALIZATION
# detection only
SecRuleEngine DetectionOnly
# prevent
# SecRuleEngine On
# REQUEST BODY HANDLING
# allow modsecurity to access request bodies
SecRequestBodyAccess On
# enable xml processor in case of xml content-type
SecRule REQUEST_HEADERS:Content-Type "(?:application(?:/soap\+|/)|text/)xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
# enable JSON Processor in case of JSON content-type 'application/json'
SecRule REQUEST_HEADERS:Content-Type "application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
# maximum request body size we will accept for buffering
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
# store up to 128 kb of request body data in memory
SecRequestBodyInMemoryLimit 131072
# what do do if the request body size is above our configured limit
SecRequestBodyLimitAction Reject
# verify that we've correctly processed the request body
SecRule REQBODY_ERROR "!@eq 0" \
"id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
# default strict settings with what we accept in the multipart/form-data
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"id:'200003',phase:2,t:none,log,deny,status:400, \
msg:'Multipart request body failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IP %{MULTIPART_INVALID_PART}, \
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"
# anything that might be a boundary
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
"id:'200004',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"
# pcre tuning avoid a potential regex dos condition
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000
# pcre tuning msc_pcre_limits_exceeded: pcre match limits were exceeded
SecRule TX:/^MSC_/ "!@streq 0" \
    "id:'200005',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"
# RESPONSE BODY HANDLING
# allow modsecurity to access response bodies (increases response time and latency)
SecResponseBodyAccess On
# which response mime types to inspect
SecResponseBodyMimeType text/plain text/html text/xml
# buffer response bodies of up to 512 kb in length
SecResponseBodyLimit 524288
# what happens when we encounter a response body larger than configured
SecResponseBodyLimitAction ProcessPartial
# FILESYSTEM CONFIGURATION
# the location where modsecurity stores temporary files
SecTmpDir /tmp/
# the location where modsecurity will keep its persistent data
SecDataDir /tmp/
# FILE UPLOADS HANDLING CONFIGURATION
# the location where modsecurity stores intercepted uploaded files
#SecUploadDir /opt/modsecurity/var/upload/
# only keep the files that were determined to be unusual
#SecUploadKeepFiles RelevantOnly
# uploaded are created with restricted permissions
#SecUploadFileMode 0600
# DEBUG LOG CONFIGURATION
# debug log configuration duplicate the error, warning and notice messages from the error log
#SecDebugLog /opt/modsecurity/var/log/debug.log
#SecDebugLogLevel 3
# AUDIT LOG CONFIGURATION
# log the transactions marked by a rule or trigger a server error (e.g., 5xx or 4xx, excluding 404, etc.)
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
# log everything we know about a transaction.
SecAuditLogParts ABDEFHIJZ
# use a single file for logging
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log
# path for concurrent audit logging.
#SecAuditLogStorageDir /opt/modsecurity/var/audit/
# MISCELLANEOUS
# commonly used application/x-www-form-urlencoded parameter
SecArgumentSeparator &
# use version 0 (zero) cookies to prevent evasion
SecCookieFormat 0
# specify your unicode code point
SecUnicodeMapFile unicode.mapping 20127
# current ModSecurity version and dependencies versions shared:
# modsecurity, web server, apr, pcre, lua, libxml2, anonymous unique id for host
SecStatusEngine On
EOF

  echo "Backing up configuration file";
  sudo cp ${_mods_enabled}/security2.conf ${_mods_available}/security2.conf.orig ;

  echo "Creating new ModSecurity mod-configuration file";
  sudo cat << EOF > ${_mods_available}/security2.conf
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
</IfModule>
EOF

  # start services
  echo "Enabling HTTP service";
  sudo systemctl start apache2 &>/dev/null;
  sudo systemctl enable apache2 &>/dev/null;
  echo "${FUNCNAME[0]} complete";
  return 0;
}

# install the lab environment
function installLab() {
  echo "Installing CVE-2022-33891 lab $(date)";
  # avoid hard coding proxy details
  # export http_proxy="${1}";

  # check if already installed
  test -f /opt/spark/.complete && (echo "[+] Setup complete" && return 0);

#  # check for proxy settings
#  if (! echo ${http_proxy}|grep -iaoP "^\K(http:\/\/[A-Za-z0-9\_\-\:\.\@]+:8888)"&>/dev/null); then
#    echo "Failed to start, missing proxy settings";
#    return 1;
#  fi;

  # configure vulnerable spark instance
  echo "Setting up Docker Spark instance";
  if (! setupSparkContainer); then
    echo "Failed to setup Spark instance";
    return 1;
  fi;

  # configure reverse apache proxy
  echo "Setting up Apache proxy";
  if (! setupApacheProxy); then
    echo "Failed to setup Apache proxy";
    return 1;
  fi;

  echo "Installation complete $(date)";
  sudo touch /opt/spark/.complete;
  sudo rm /tmp/cve-setup.sh &>/dev/null;
#  history -c;
  return 0;
}
installLab
# install the lab
# installLab ${1} 2>&1>> ${install_log};
