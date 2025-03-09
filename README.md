# Diploma Thesis

This project focuses on evaluating the security configuration of a MySQL database system, ensuring it aligns with best practices. The tool analyzes the setup and presents its findings in a clear and structured manner.
The generated report provides essential insights to help identify and rectify potential misconfigurations.

## How to Run

To execute the security checks, ensure that a MySQL database instance is running. Database credentials can be supplied using command-line arguments.

For tests requiring access to configuration files (e.g., `my.ini`), specify their location using the `--path` flag. If no path is provided, the default configuration directory will be used.  

If the necessary database connection or configuration files are not accessible, the tool will automatically skip tests dependent on these resources.

### Installation

```sh
git clone https://gitlab.com/hc-tools1/hc-mysql
cd $_
```

### Windows

For Non-existing database :
```sh
python .\main.py --setup-db --user <username> --password <password> --host <host> --port <port>
```

In case that all values are default you can use just:
```sh
python .\main.py --setup-db 
```

For already existing database:
```sh
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
- argparse
- configparser
- logging
- mysql-connector-python
- requests
- pyyaml
- matplotlib
- pylatex
- psutil
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
