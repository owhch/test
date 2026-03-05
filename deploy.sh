#!/bin/bash
# deploy.sh — запусти на VPS для обновления сайта
cd /root/mysite
source venv/bin/activate
git pull
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --noinput
sudo systemctl restart gunicorn
echo "✅ Деплой завершён!"
