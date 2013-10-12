#!/bin/bash

## Create the default database
pacman -Syu
## Install Git
pacman -S git
## Install Python2
pacman -S python2

pacman -S binutils

pacman -S gcc

wget https://aur.archlinux.org/packages/py/pylibpcap/pylibpcap.tar.gz
tar -zxvf ./pylibpcap.tar.gz
cd pylibpcap
makepkg

pacman -U ./pylibpcap-0.6.4-1-any.pkg.tar.xz

cd ~

git clone https://github.com/jeffharwell/polycom_monitor.git

