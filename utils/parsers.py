from utils.utils import exec_sql_query
import pprint
import utils.errors as errors

def parse_database_privileges(self):
    query = """
    SELECT grantee, table_schema, table_name, privilege_type
    FROM information_schema.table_privileges
    WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys');
    """

    rows = exec_sql_query(self.conn, query)
    parsed_data = {}

    for grantee, table_schema, table_name, privilege_type in rows:
        # Pokud ještě grantee nemá záznam, vytvoříme prázdný seznam
        if grantee not in parsed_data:
            parsed_data[grantee] = []

        # Najdeme, jestli už existuje záznam pro tabulku
        table_entry = next((entry for entry in parsed_data[grantee] if entry["table_name"] == table_name), None)

        if table_entry:
            # Pokud existuje, přidáme privilegium
            table_entry["privilege_type"].append(privilege_type)
        else:
            # Pokud neexistuje, vytvoříme nový záznam
            parsed_data[grantee].append({
                "table_schema": table_schema,
                "table_name": table_name,
                "privilege_type": [privilege_type]
            })
    #pprint.pprint(parsed_data)
    return parsed_data
    
def parse_mysql_conf(self, path):
    config = {}
    try:
        with open(path, 'r') as file:
            for line in file:
                stripped_line = line.strip()
                if stripped_line.startswith('#') or not stripped_line:
                    continue
                if '#' in stripped_line:
                    stripped_line = stripped_line.split('#', 1)[0].strip()
                
                parts = stripped_line.split('=', 1)
                if len(parts) == 2:
                    key, value = parts
                    key = key.strip()
                    value = value.strip()

                    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    
                    config[key] = value
    except FileNotFoundError:
        raise errors.FileNotFound(path) 
    return config

def parse_auth_methods(self):
    query = """
    SELECT user, host, plugin
    FROM mysql.user;
    """

    rows = exec_sql_query(self.conn, query)
    parsed_data = {}

    for user, host, plugin in rows:
        # Pokud ještě user nemá záznam, vytvoříme prázdný seznam
        if user not in parsed_data:
            parsed_data[user] = [host, plugin]

    #pprint.pprint(parsed_data)
    return parsed_data


def parse_empty_passwords(self):
    query = """
        SELECT user, host, plugin, authentication_string
        FROM mysql.user
        WHERE (authentication_string = '' OR authentication_string IS NULL);"""

    rows = exec_sql_query(self.conn, query)
    parsed_data = {}

    for user, host, plugin, authentication_string in rows:
        if user not in parsed_data:
            parsed_data[user] = [host, plugin, authentication_string]

    return parsed_data