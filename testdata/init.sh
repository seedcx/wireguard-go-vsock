#!/bin/bash

wireguard-go-vsock -f -n tcp "$1" &
