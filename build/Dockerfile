FROM python:3.13-slim-bookworm

RUN apt-get update && \
    apt-get install -y build-essential wget default-jdk flex \
    bison graphviz graphviz-dev texlive-font-utils xutils-dev git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY ./build/XSB-5.0.tar.gz ./
RUN tar -xzf XSB-5.0.tar.gz
WORKDIR /root/XSB/build
RUN ./configure && \
    ./makexsb && ./makexsb install
ENV PATH="$PATH:/root/XSB/bin/"

WORKDIR /root
COPY ./build/mulval/ /root/mulval
ENV MULVALROOT=/root/mulval
ENV PATH=$PATH:"$MULVALROOT/bin":"$MULVALROOT/utils"
WORKDIR /root/mulval
RUN make && chmod +x ./utils/graph_gen.sh

WORKDIR /root/CTIgraph
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    rm ./requirements.txt && rm -rf ./build

COPY . .

CMD ["bash"]