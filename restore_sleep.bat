@echo off
echo ========================================
echo Повернення нормальних налаштувань Windows
echo ========================================
echo.
echo Цей скрипт повертає нормальні налаштування сну
echo Потрібні права адміністратора!
echo.
pause

echo.
echo Відновлюю налаштування...
powercfg /change standby-timeout-ac 30
powercfg /change standby-timeout-dc 15
powercfg /hibernate on

echo.
echo ========================================
echo Готово! Налаштування відновлено.
echo ========================================
echo.
pause

