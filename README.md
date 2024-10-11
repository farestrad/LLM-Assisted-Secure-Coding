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

## Setup Ollama on the server (just copy paste these commands)
- ```sudo apt update```
- ```curl -fsSL https://ollama.com/install.sh | sh```
- ```ollama --version```
- ```ollama run llama3```
```sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```  this ensures there is freed up space
- run this to test if it works ```ollama run llama3 "Summarize the importance of space exploration."```

## Setup a public api
You would need to ensure you copy the ipv4 address from your digital ocean dashboard should look like this 134.122.36.xxx
- ```sudo sed -i '/^\[Service\]/,/^\[Install\]/s|^ExecStart=.*|ExecStart=/usr/local/bin/ollama serve|' /etc/systemd/system/ollama.service && \
echo 'Environment="HOST=0.0.0.0"' | sudo tee -a /etc/systemd/system/ollama.service > /dev/null
```
- ```sudo systemctl daemon-reload
sudo systemctl restart ollama```
- it shouldnt show any red warnings ```sudo systemctl status ollama```
- when you run ```sudo ss -tuln | grep 11434``` you should get an output like this ```tcp   LISTEN 0      4096       127.0.0.1:11434      0.0.0.0:* ```
- 



# code-llama-integration README

This is the README for your extension "code-llama-integration". After writing up a brief description, we recommend including the following sections.

## Features

Describe specific features of your extension including screenshots of your extension in action. Image paths are relative to this README file.

For example if there is an image subfolder under your extension project workspace:

\!\[feature X\]\(images/feature-x.png\)

> Tip: Many popular extensions utilize animations. This is an excellent way to show off your extension! We recommend short, focused animations that are easy to follow.

## Requirements

If you have any requirements or dependencies, add a section describing those and how to install and configure them.

## Extension Settings

Include if your extension adds any VS Code settings through the `contributes.configuration` extension point.

For example:

This extension contributes the following settings:

* `myExtension.enable`: Enable/disable this extension.
* `myExtension.thing`: Set to `blah` to do something.

## Known Issues

Calling out known issues can help limit users opening duplicate issues against your extension.

## Release Notes

Users appreciate release notes as you update your extension.

### 1.0.0

Initial release of ...

### 1.0.1

Fixed issue #.

### 1.1.0

Added features X, Y, and Z.

---

## Following extension guidelines

Ensure that you've read through the extensions guidelines and follow the best practices for creating your extension.

* [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)

## Working with Markdown

You can author your README using Visual Studio Code. Here are some useful editor keyboard shortcuts:

* Split the editor (`Cmd+\` on macOS or `Ctrl+\` on Windows and Linux).
* Toggle preview (`Shift+Cmd+V` on macOS or `Shift+Ctrl+V` on Windows and Linux).
* Press `Ctrl+Space` (Windows, Linux, macOS) to see a list of Markdown snippets.

## For more information

* [Visual Studio Code's Markdown Support](http://code.visualstudio.com/docs/languages/markdown)
* [Markdown Syntax Reference](https://help.github.com/articles/markdown-basics/)

**Enjoy!**
