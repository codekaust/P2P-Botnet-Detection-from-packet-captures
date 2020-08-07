#!/bin/bash

echo 'Create Virtual Environment'
sudo apt install -y virtualenv
virtualenv --python=python3.6 venv

source venv/bin/activate
echo 'Virtual Enviornment Created and Started'

echo 'Installing Tshark'
sudo apt install -y tshark

echo 'Installing Dependencies'
pip install -r requirements.txt
