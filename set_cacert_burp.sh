#!/bin/bash

echo "[>] Geando certificados PEM apartir do DER"
openssl x509 -inform DER -in burp.cer -out burp.pem
wait

burp=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem |head -1).0
wait
echo "[>] Renomeando burp.pem para $burp"
mv burp.pem $burp

echo "[>] Reiniciando o Device..."
adb reboot
wait

echo "[!] Pressione enter apos o Device ter reiniciado:"
read 
adb root
wait
echo "[>] Remontando particoes para escrita..."
# adb remount
adb shell "mount -o rw,remount /"
wait

echo "[>] Enviando certificados..."
adb push $burp /system/etc/security/cacerts
wait

adb remount
wait

echo "[>] Modificando permissoes..."
adb shell "chmod 644 /system/etc/security/cacerts/$burp"


