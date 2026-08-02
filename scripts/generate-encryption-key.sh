#!/bin/sh
openssl rand -hex 32 > config/encryption.key
chmod 600 config/encryption.key
