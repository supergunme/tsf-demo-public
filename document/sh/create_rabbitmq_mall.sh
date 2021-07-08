#!/bin/bash
rabbitmqctl add_user mall mall &&
rabbitmqctl set_user_tags mall administrator &&
rabbitmqctl add_vhost /mall &&
rabbitmqctl set_permissions -p /mall mall '.*' '.*' '.*'