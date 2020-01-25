# Wordpress Subpath Auditor

Wordpress Subpath Auditor is a home made tool one can use in order to quickly detect common sources and sinks within a choosen subpath (plugin, theme, etc). \
It works by patching php code (functions epilogue) in order to leak the code and parameters that a pré/post auth user can access. 


# Dependencies

```bash
# Add lokal as your localhost hostname
# Some browser doesn't like catching localhost traffic..
sudo echo "127.0.0.1 lokal" >> /etc/hosts

# Install docker and docker-compose
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu disco stable"
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.0/docker-compose-Linux-x86_64" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install dependencies
sudo apt install virtualenv git python3

# First time setup
virtualenv -p python3 .py3
source .py3/bin/activate
pip install -r requirements.txt
```


# Use WoSuAu

```bash
# Start the wordpress docker with our files
sudo rm -rf html
git clone https://github.com/WordPress/WordPress html
cp docker-compose.yml html
sudo chmod -R 777 html
sudo docker-compose -f html/docker-compose.yml up

# Fix the files
cat >> html/wp-config.php << EOF
define('FS_METHOD', 'direct');
EOF

# Prepare for backups!
# Visit http://lokal:8000/ and setup root:root
# Install your plugins and activate them
pushd html && git add . && git commit -m "WoSuAu_init" && popd

# Or restore files if the plugin_auditor crashed
pushd html && git checkout . && popd

# Run WoSuAu (assuming docker-compose is up)
source .py3/bin/activate
python wo_su_au.py -u http://lokal:8000/ -s html/wp-content/plugins
```

# Use Direct Code Access

Find out if a file contains direct executable php code. 

```bash
source .py3/bin/activate
python direct_code_access.py -s html/wp-content/plugins
```


# HTTP logger (initial POC)

The initial POC was using dirty bash and exec/curl in order to leah the logs via HTTP requests

```bash
# Simple netcat listener, this wa missing requests as it's single threaded
while true; do nc -q 0 -lvp 8888 2>&1 <<< "ok" | grep --color=never GET | cut -d" " -f 2 | cut -c 3- | base64 -d && echo ; done

# Simple listener server, multi threaded but limited as it's NOT the intended purpose of http.server
python3 -m http.server 8888  | grep GET
```

```php
// Php HTTP exfiltrator uning exec and curl
exec("curl http://listener:8888/?" . base64_encode("get=" . json_encode($_GET)));
```


# TODO

- Move "contains" to regex, like for `backticks` or `"fct_name"(fct_params)`)
- Improve speed (limitation with logs.txt LOCK)

# Limiations

## The crawler is GET-only

Yup, I don't want to code one from scratch in this tool, use Burp, Archni, ... \
Tips : Burp in authentified crawl + audit mode, plus extension logger++ makes it easy to replay requests for a given url 

## How can I proxy WoSuAu in burp ? 

HTTP_PROXY=http://127.0.0.1:8080 python wo_su_au.py -u http://lokal:8000/ -s html

## There is no output format in the options

Yeah, just go for `python wo_su_au.py URL | tee output.txt` and you'll be fine. 

## I want to replay the request that reached a specific path

BurpSuite -> Extender -> logger++ -> search by URL -> SendToRepeater



