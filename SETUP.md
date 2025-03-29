## Steps to Resolve issues
- run ```npm install```
- ```npm install node-fetch@^2```
- ```npm run compile```
- ```npm install --save-dev @types/amplitude-js```

## Updates and fetches latest commit
- ```git fetch origin```
- ```git reset --hard origin/main```

## How to create a pull request
- ```git checkout -b <branch-name>```
- ```git add .```
- ```git commit -m "Description of the changes made"```
- ```git push origin <branch-name>```



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
- using gcp set 2vCPU + 8GB RAM 30GB persistent balanced disk (i think this is best and cost efficient.)
## Setup Ollama on the server (just copy paste these commands)
- ```curl -fsSL https://ollama.com/install.sh | sh```
- ```service ollama start```
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
  run sudo nano /etc/systemd/system/ollama.service and change the service to 
```
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
ExecStart=/usr/local/bin/ollama serve
```

- ```sudo systemctl daemon-reload```
- ```sudo systemctl restart ollama```
- ```ss -tulnp | grep 11434```
everything should be working.

## Test
- ```curl -X POST http://178.128.231.xxx:11434/api/generate -d '{
  "model": "llama3",
  "prompt": "Why is the sky blue?",
  "stream": true}'
  ```

## Steps to setup reserve proxy
```sudo apt update && sudo apt install nginx -y```

```sudo systemctl status nginx```

```sudo nano /etc/nginx/sites-available/ollama```

add in this 

```
server {
    listen 80;
    server_name your-server-ip;  # Replace with your public IPv4 address

    location /api/generate {
        proxy_pass http://127.0.0.1:3000/generate;  # Forward to custom API
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://127.0.0.1:11434;  # Forward other requests to Ollama directly
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```sudo apt install python3 python3-pip -y```

```pip3 install flask requests```

```mkdir ~/shadow-ml-api```

```cd ~/shadow-ml-api```

```nano server.py```

# code-llama-integration README

This is the README for your extension "code-llama-integration". After writing up a brief description, we recommend including the following sections.

## Features
