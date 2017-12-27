#!/bin/bash

delete() {
    rm -rf ./auth
}

build() {
    go build ./auth.go
}

start_auth() {
   ./auth
}

delete
sleep 1
build
sleep 3
start_auth

