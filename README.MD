# Test Api - The test workbench 
Test tool for simulating errors and exceptional situations on a Linux system

** Work in progress **

## Installing after cloning

```
cd /path/to/test_api
virtualenv tapi_env
./tapi_env/bin/pip install flask
./tapi_env/bin/pip install python-iptables
```

## Running the server
```
chmod +x app.py
sudo ./app.py
```

## Firewall functions

### List current rules

```
http://127.0.0.1:5000/firewall/api/v1.0/rules/
```

### Add a new rule

#### Drop packets coming to port 80
```
curl -i -H "Content-Type: application/json" -X PUT -d '{"proto":"tcp", "dport":"80", "in_iface":"wan1", "target":"DROP", "matches": [{"comment": "deny dport 80", "name": "comment"}]}' http://127.0.0.1:5000/firewall/api/v1.0/rules/INPUT
```

#### Reject packets coming to port 80
```
curl -i -H "Content-Type: application/json" -X PUT -d '{"proto":"tcp", "dport":"80", "in_iface":"wlan1", "target":"REJECT", "matches": [{"comment": "reject dport 80", "name": "comment"}]}' http://192.168.0.13:80/firewall/api/v1.0/rules/INPUT
```

#### Reject traffic from a given source IP
```
curl -i -H "Content-Type: application/json" -X PUT -d '{"proto":"tcp", "src":"192.168.0.101", "target":"REJECT", "matches": [{"comment": "reject dsrc x.x.x.101, "name": "comment"}]}' http://192.168.0.13:80/firewall/api/v1.0/rules/INPUT
```

#### Reject traffic from a given source IP and destination port
```
curl -i -H "Content-Type: application/json" -X PUT -d '{"proto":"tcp", "dport":"80", "src":"192.168.0.101", "target":"REJECT", "matches": [{"comment": "reject dource x.x.x.101 and dport 80", "name": "comment"}]}' http://92.168.0.13:80/firewall/api/v1.0/rules/INPUT
```

### Flush configuration 

```
http://127.0.0.1:5000/firewall/api/v1.0/flush/
```

## Execute arbitrary operating system commands
```
curl -i -H "Content-Type: application/json" -X PUT -d '{"cmd":"ls -al"}' http://192.168.0.13:80/os/api/v1.0/exec
```

## Work with files
### Check the existence of a file
### Search values in log files
```
curl -i -H "Content-Type: application/json" -X PUT -d '{"p":"/var/log/syslog","e":"DHCPv[4|5]"}' http://192.168.0.13:80/files/api/v1.0/grep
```
### Check file content asynchronously
### Check that certain values are not in the log file
### Replace content within a file
### Check the existence of a file
### Delete a file or folder

## Service Management
### Start / Stop Services

# Sources used at the development

```
http://blog.miguelgrinberg.com/post/designing-a-restful-api-with-python-and-flask
https://github.com/ldx/python-iptables
```
