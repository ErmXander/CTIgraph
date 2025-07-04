# Installation
### 1. Clone the Repository:
```bash
git clone https://github.com/ErmXander/CTIgraph.git
cd CTIgraph
```
### 2. Install Python requirements:
```bash
pip install -r requirements.txt
```
### 3. Install MulVAL:
#### 3.1 Install dependencies:
```bash
sudo apt install build-essential default-jdk flex bison graphviz texlive-font-utils xutils-dev git
```
#### 3.2 Install XSB:
```bash
wget "https://sourceforge.net/projects/xsb/files/xsb/5.0%20%28Green%20Tea%29/XSB-5.0.tar.gz/download" -O - | \
sudo tar -zx -C /usr/local/bin
sudo mv /usr/local/bin/XSB /usr/local/bin/xsb-5.0.0
cd /usr/local/bin/xsb-5.0.0
sudo ./configure -prefix=/usr/local/bin
sudo ./makexsb
sudo ./makexsb install
```
#### 3.3 Set-up environment variable:
Add the following lines to ```.bashrc```:
```bash
export MULVALROOT=~/mulval
export PATH=$PATH:"$MULVALROOT/bin":"$MULVALROOT/utils":/usr/local/bin/xsb-5.0.0/bin
```
#### 3.4 Compile MulVAL:
Pull MulVAL repo and patch its files:
```bash
cd ~ && git clone https://github.com/risksense/mulval.git
cd mulval
wget "https://patch-diff.githubusercontent.com/raw/risksense/mulval/pull/9.patch" -O - | git apply -
```
Compile:
```bash
make
```
#### 3.5 Replace graph generation script:
In order to allow the generation of Attack Graphs using negated predicates MulVAL's graph_gen.sh (the graph generation script) was slightly modified.
The modified version is found in  ```CTIgraph/utils ``` and should be used to replace the one used by MulVAL (found in ```$MULVALROOT/utils```).

## Docker Setup
A Dockerfile is provided in ```build/```. This Dockerfile can be used to build an image:
```bash
git clone https://github.com/ErmXander/CTIgraph.git
cd CTIgraph
sudo docker build -t ctigraph:latest -f ./build/Dockerfile .
```

The script ```utils/docker_run.sh``` can be used to run a container using this image and interact with the tool via CLI.
