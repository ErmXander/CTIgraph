#!/bin/sh
kb_path=${kb_path:="./kb"}
io_path=${io_path:="./tests"}
sudo docker run --rm --name ctigraph -it -v "$kb_path":/root/CTIgraph/kb -v "$io_path":/root/CTIgraph/tests ctigraph