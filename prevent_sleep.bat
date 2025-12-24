@echo off
echo ========================================
echo Налаштування Windows для роботи кафе
echo ========================================
echo.
echo Цей скрипт запобігає переходу ноутбука в сон
echo Потрібні права адміністратора!
echo.
pause

echo.
echo Встановлюю налаштування...
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /hibernate off

echo.
echo ========================================
echo Готово! Сон вимкнено.
echo ========================================
echo.
echo Щоб повернути нормальні налаштування, запустіть restore_sleep.bat
echo.
pause

