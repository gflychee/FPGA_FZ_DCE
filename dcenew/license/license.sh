#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
$DIR/exanic-fpga-controller -k $DIR/exanic-fpga-controller.key 
