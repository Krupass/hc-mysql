import os
from utils.global_logger import logger
import psycopg2
from utils.global_logger import logger
import yaml

def convert_dict_to_yaml(data):
    logger().info("converting data to yaml")
    try:
        yaml_content = yaml.dump(data, default_flow_style=False)
        print(yaml_content)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def sub_array(have, need):
    if not need:
        return True
    for i in need:
        if i not in have:
            return False
    return True

def convert_dict_to_yaml(data):
    logger().info("converting data to yaml")
    try:
        yaml_content = yaml.dump(data, default_flow_style=False)
        print(yaml_content)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_postgresql_version(base_path):
    if not os.path.exists(base_path):
        logger().warning("MySQL config directory does not exist")
        exit("MySQL config directory does not exist")
    dir = os.listdir(base_path)
    # todo: choose latest version?
    if len(dir) == -1:
        logger().warning("No mysql version installed")
        exit("No mysql version installed")
    return dir[-1]


def get_default_mysql_config_path():
    if os.name == 'nt':
        base = r"C:\ProgramData\MySQL"
        return str(os.path.join(base, get_postgresql_version(base), 'data'))
    elif os.name == 'posix':
        return "/etc/mysql/my.cnf"
    else:
        logger().info("unknown operational system: " + os.name)
        return None

def get_postgresql_version_cmd(base_path):
    import platform, subprocess
    current_platform = platform.system()
    try:
        if current_platform == 'Windows':
            pg_config_cmd = os.path.join(os.path.dirname(base_path), r"bin\\pg_config")
            subprocess.run([pg_config_cmd, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        else:  # Assuming Linux
            pg_config_cmd = 'pg_config'
            subprocess.run([pg_config_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        version_output = subprocess.check_output([pg_config_cmd, '--version'], text=True)

        version_lines = version_output.strip().split('\n')
        postgresql_version = version_lines[0].split()[-1]
        return str(postgresql_version)

    except subprocess.CalledProcessError as e:
        raise str(e)


def rewrite_file(filename, content):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
    file_path = os.path.join(parent_dir, filename)
    with open(file_path, "w") as file:
        file.write(content)

# mozna pridat error handling vyhledove
def exec_sql_query(conn, query):

    try:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        logger().info(f"executed query: \"{query}\" with connection {conn}")
        cursor.close()
        # print(f"result {rows}")
        return rows 
    except psycopg2.Error as e:
        logger().warning(f"error executing query: \"{query}\" with connection {conn}")
    return None

def build_connect_string(args):
    components = {
        'dbname': getattr(args, 'dbname', None),
        'user': getattr(args, 'user', None),
        'password': getattr(args, 'password', None),
        'host': getattr(args, 'host', None),
        'port': getattr(args, 'port', None)
    }
    
    
    connection_string = ' '.join(f"{key}={value}" for key, value in components.items() if value is not None)
    logger().info(f"Connection string prepared: {connection_string}")
    return connection_string