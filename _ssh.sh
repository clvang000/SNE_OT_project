#!/bin/bash
ssh-keygen -f msf;
ssh-copy-id -i msf root@192.168.70.70;
ssh -i msf root@192.168.70.70;
