#!/bin/sh
protoc --proto_path=./protos --cpp_out=./src ./protos/AudioQoS.proto
