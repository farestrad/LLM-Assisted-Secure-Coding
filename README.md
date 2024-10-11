## Steps to Resolve issues
- run ```npm install```
- ```npm install node-fetch@^2```
- ```npm run compile```


## Steps to Deploying the server
- go to https://www.digitalocean.com and scroll down till you see Sign up and get $200 in credit for your first 60 days with DigitalOcean.* click the button and sign up this gives you a $200 credit
- after setup click first project
- then click spin up a droplet
- choose Toronto as your region and click basic droplet type and premium intel for cpu options and click the $64 per month option
- set a root password (you wont need it since you are loggin into the console directly than SSH wise)
- click the creatre droplet button.
- now your droplet should be on and you can now access your console
- it should look something like this ```ubuntu-s-4vcpu-8gb-240gb-intel-tor1-01``` click it.
- now click access and click launch droplet console

## Setup Ollama on the server (just copy paste these commands
- ```curl -fsSL https://ollama.com/install.sh | sh```
- ```ollama run llama3```
if you try tunninmg ollama run llama3 and it gives you an error after success log in console then run the below command to fill space
```sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Setup a public api
You would need to ensure you copy the ipv4 address from your digital ocean dashboard should look like this 134.122.36.xxx
- ```mkdir -p /etc/systemd/system/ollama.service.d```
- ```echo [Service] >>/etc/systemd/system/ollama.service.d/environment.conf```
- ```echo Environment=OLLAMA_HOST=0.0.0.0:11434 >>/etc/systemd/system/ollama.service.d/environment.conf```
- 
- ```sudo systemctl daemon-reload```
- ```sudo systemctl restart ollama```
everything should be working.

## Test
- ```curl -X POST http://178.128.231.xxx:11434/api/generate -d '{
  "model": "llama3",
  "prompt": "Why is the sky blue?",
  "stream": true}'
  ```



# code-llama-integration README

This is the README for your extension "code-llama-integration". After writing up a brief description, we recommend including the following sections.

## Features
