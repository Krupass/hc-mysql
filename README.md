### Installation

```sh
git clone https://gitlab.com/hc-tools1/hc-mysql
cd $_
```

### Windows

For Non-existing database :
```ps
python .\main.py --setup-db --user <username> --password <password> --host <host> --port <port>
```
In case that all values are default you can use just:
```ps
python .\main.py --setup-db 
```

For already existing database:
```ps
python .\main.py --user <username> --password <password> --host <host> --port <port>
```

## Flags
  -p \<PATH\>, --path \<PATH\>  Select custom path to MySQL configuration.
  
  --dbname \<DBNAME\>       Specify the database name
  
  --user \<USER\>            Specify the user
  
  --password \<PASSWORD\>    Specify the password
  
  --host \<HOST\>            Specify the host
  
  --port \<PORT\>            Specify the port

  --setup-db            Creates experimental database (development feature)

## Dependencies
- python 3+
- pdflatex (optional)

### Python Libraries
-- argparse
-- configparser
-- logging
-- mysql-connector-python
-- requests
-- pyyaml
-- matplotlib
-- pylatex
-- psutil
#### Installation
Following commands iterate over `dependencies` file stored in this directory and performs `pip install` in order to install them.
##### Windows CMD
```
for /F %i in (dependencies) do pip install %i
```
##### Windows Powershell
```
Get-Content dependencies | ForEach-Object { pip install $_ }
```
