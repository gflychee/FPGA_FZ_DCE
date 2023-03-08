#!/bin/bash
/usr/local/bin/exanic-config exanic0:0 up
/usr/local/bin/exanic-config exanic0:1 up
/usr/local/bin/exanic-config exanic0:0 promisc on
/usr/local/bin/exanic-config exanic0:1 promisc on
