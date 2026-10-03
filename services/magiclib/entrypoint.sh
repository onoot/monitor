#!/bin/sh

echo "Waiting for postgres..."

while ! nc -z postgres 5432; 
do
    sleep 0.1
done
echo "PostgreSQL started"

exec "$@"
# Запускаем Gunicorn
# exec gunicorn --bind 0.0.0.0:1337 --log-level debug run:app
