This is how to setup the machine learning model to work with the ollama server. 
This already assumes you have ollama and a model running on port 11434 and your using a ubuntu server
for other server types should be easy to figure out using chatgpt

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
