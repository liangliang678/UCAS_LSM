#!/bin/bash

gcc -o role_manager role_manager.c
mkdir /etc/LiangLSM
touch /etc/LiangLSM/user2role
touch /etc/LiangLSM/role2permission
touch /etc/LiangLSM/control
