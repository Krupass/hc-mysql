import os
import pprint
import re
import mysql.connector
import requests
from utils.global_logger import logger
from utils.utils import exec_sql_query
from utils.utils import get_mysql_version_cmd as get_mysql_version
import utils.parsers as parser
import latex_generator as latex_g
import pprint


def unlimited_superuser_access(sess):
    results = ["\\begin{itemize}"]
    all_tables = {entry['table_name'] for user in sess.privileges.values() for entry in user}
    admins = {key: value for key, value in sess.privileges.items() if 'admin' in key.lower()}
    for user_name, privileges in sess.privileges.items():
        if user_name in admins:
            admin_tables_accessed = {entry['table_name'] for entry in privileges}
            admin_rights = {tuple(entry['privilege_type']) for entry in privileges}

            access_to_all_tables = admin_tables_accessed == all_tables
            diverse_privileges = len(admin_rights) > 1

            result = f"\\item {latex_g.escape_latex(user_name)} - Access to all tables: {'Yes' if access_to_all_tables else 'No'}"
            if len(admins) > 1:
                result += f", Diverse privileges: {'Yes' if diverse_privileges else 'No'}\n"
            else:
                result += "\n"
            results.append(result)
    results.append("\end{itemize}")
    details = '\n'.join(results)

    return {
        'compliant' : False, 
        'config_details' : details
    }


def check_if_ssl_is_enabled(sess):
    # Rozšířený seznam SSL nastavení
    ssl_settings_names = ['ssl', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_prefer_server_ciphers']
    db_ssl_settings = {key: value for key, value in sess.mysql_conf.items() if key in ssl_settings_names}

    # Inicializace proměnných
    compliant = True
    details = "\\begin{tabular}{|l|l|l|l|}\n\\hline\n"
    details += "\\textbf{Configuration Name} & \\textbf{DB Setting} & \\textbf{Recommended Setting} & \\textbf{Compliant} \\\\\n\\hline\n"
    
    # Doporučené hodnoty pro SSL konfigurace
    recommended_values = {
        'ssl': 'on',
        'ssl_cert_file': '<cert file>',
        'ssl_key_file': '<key file>',
        'ssl_ca_file': '<root cert file>',
        'ssl_prefer_server_ciphers': 'on'
    }

    for setting in ssl_settings_names:
        db_value = db_ssl_settings.get(setting, 'N/A')
        recommended_value = recommended_values.get(setting, 'N/A')
        
        # Pro souborové nastavení zkontrolujte, zda je soubor definován
        if setting in ['ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_crl_file'] and db_value != '':
            is_compliant = True  # Soubor je definován
        else:
            is_compliant = db_value == recommended_value
        
        compliant &= is_compliant
        if setting in ['ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_crl_file'] and db_value == 'N/A':
            checkmark_or_cross = "$\\times$"  # Soubor není definován
        else:
            checkmark_or_cross = "$\\checkmark$" if is_compliant else "$\\times$"

        details += f"{latex_g.escape_latex(setting)} & {latex_g.escape_latex(db_value)} & {latex_g.escape_latex(recommended_value)} & {checkmark_or_cross} \\\\\n\\hline\n"

    details += "\\end{tabular}"

    return {
        'compliant': compliant,
        'config_details': details
    }


def check_verbose_errors(sess):
    # aby se nezobrazovali errory na klientske strane, je potreba nastavit log_min_error_statement = 'PANIC' a client_min_messages = error
    compliant = True
    client_side_log_settings = ['log_min_error_statement', 'log_min_messages']
    verbose_log_min_messages = ['debug5', 'debug4', 'debug3', 'debug2', 'debug1', 'debug', 'info', 'notice', 'warning']
    verbose_log_min_error_statement = ['error', 'warning', 'notice', 'info', 'log', 'debug', 'debug1', 'debug2', 'debug3', 'debug4', 'debug5']
    details = ""
    client_side_errors = {key: value for key, value in sess.mysql_conf.items() if key in client_side_log_settings}
    log_min_messages = client_side_errors.get('log_min_messages', '').lower()
    log_min_error_statement = client_side_errors.get('log_min_error_statement', '').lower()

    if log_min_messages in verbose_log_min_messages or log_min_error_statement in verbose_log_min_error_statement:
        # error se vrati v aplikaci
        compliant = False
    
    if not bool(client_side_errors):
        # zadny error handling nastaveny neni
        details += "\nAplication does not set up parameters for verbosity of errors."
        compliant = False
    else:
        details += "\nConfiguration of error handling allows for user to receive non-generic errors"
        details += latex_g.mysql_conf_dict_to_latex_table(client_side_errors)
    
    #print(client_side_errors)
    return {
        'compliant' : compliant, 
        'config_details' : details
    }




def check_log_configuration(sess):
    recommended_values = {
        'log_statement': 'ddl',
        'log_duration': 'on',
        'log_min_duration_statement': '0',  
        'log_connections': 'on',
        'log_disconnections': 'on',
        'log_lock_waits': 'on',
        'log_temp_files': '0'
    }
    
    log_values = {key: value for key, value in sess.mysql_conf.items() if key in recommended_values}
    print("LOGS ", log_values)
    compliant = True
    details = "\\begin{tabular}{|l|c|c|c|}\n\\hline\n\\textbf{Configuration Name} & \\textbf{DB Setting} & \\textbf{Recommended Setting} & \\textbf{Compliant} \\\\\n\\hline\n"
    
    for key, recommended_value in recommended_values.items():
        actual_value = log_values.get(key, 'N/A')
        is_compliant = actual_value == recommended_value
        compliant &= is_compliant
        checkmark_or_cross = "$\\checkmark$" if is_compliant else "$\\times$"
        details += f"{latex_g.escape_latex(key)} & {latex_g.escape_latex(actual_value)} & {latex_g.escape_latex(recommended_value)} & {checkmark_or_cross} \\\\\n\\hline\n"
    
    details += "\n\\end{tabular}"
    
    return {
        'compliant': compliant,
        'config_details': details
    }


def check_pg_file_access(sess):
    compliant = True
    query = "SELECT pg_read_file('mysql.conf', 0, 1000);"
    rows1 = exec_sql_query(sess.conn, query)
    details = ""
    if rows1 != None:
        details += "\\textbf{Test was able to read mysql.conf from SQL query}"
        compliant = False
    return {
        'compliant' : compliant, 
        'config_details' : details
    }


def check_if_user_has_pg_execute_server_program(sess):
    compliant = False
    query = """
        SELECT r.rolname AS member_role_name  
        FROM pg_roles r  
        JOIN pg_auth_members am ON r.oid = am.member  
        JOIN pg_roles r2 ON am.roleid = r2.oid  
        WHERE r2.rolname = 'pg_execute_server_program';  
    """
    rows = exec_sql_query(sess.conn, query)
    if len(rows) != 0:
        details = "\\begin{itemize}\n"
        for r in rows:
            # Assuming you want to concatenate all elements in the tuple
            details += "\\item " + latex_g.escape_latex(' '.join(map(str, r))) + "\n"
        details += "\\end{itemize}\n"

        return {
            'compliant' : False, 
            'config_details' : details
        }
    return {
        'compliant' : True, 
        'config_details' : ""
    }
        

    

# it shouldn't have backup_directory as parameter but session
def check_mysql_backup(backup_directory):
    compliant = False
    try:
        backup_files = os.listdir(backup_directory)
    except FileNotFoundError:
        logger().warning("Provided backup directory was not found.")
    if backup_files:
        compliant = True
    return {
        'compliant' : compliant, 
        'config_details' : ""
    }
    

def check_user_permissions(sess):
    connection = sess.conn
    cur = connection.cursor()
    query = """
            SELECT user, host, select_priv,insert_priv,
            update_priv, delete_priv, create_priv, drop_priv, grant_priv
            FROM mysql.user;"""

    cur.execute(query)
    result = cur.fetchall()
    cur.close()

    parsed_data = {}

    for user, host, select_priv, insert_priv, update_priv, delete_priv, create_priv, drop_priv, grant_priv in result:
        if user not in parsed_data:
            parsed_data[user] = [host, select_priv, insert_priv, update_priv, delete_priv, create_priv, drop_priv,
                                 grant_priv]



    return {
        'compliant' : False, 
        'config_details' : latex_g.privilege_dict_to_latex_table(sess.privileges)
    }

# sess contains connection to database
def check_pg_crypto_extension(sess):
    compliant = True
    query = "SELECT * FROM pg_catalog.pg_extension WHERE extname LIKE 'pgcrypto';"
    rows = exec_sql_query(sess.conn, query)
    if not bool(rows):
        compliant = False
    return {
        'compliant' : compliant, 
        'config_details' : ""
    }

def test_transit_encryption(sess):
    connection = sess.conn
    cur = connection.cursor()
    query = "SELECT user, host, ssl_type FROM mysql.user;"
    compliant = None
    was_compliant_false = False

    logger().info("Testing transit encryption...")

    cur.execute(query)
    result = cur.fetchall()
    cur.close()

    latex_table = "\\begin{center}\n\\begin{tabular}{|l|l|l|}\n\\hline\n"
    latex_table += "\\textbf{USER} & \\textbf{HOST} & \\textbf{SSL\\_TYPE} \\\\ \\hline\n"

    for row in result:
        user, host, ssl_type = row
        if not user.strip().startswith("mysql."):
            if ssl_type.strip().lower() == "x509" or ssl_type.strip().lower() == "ssl":
                compliant = True
                print("User: " + user.strip() + " has ssl_type: " + ssl_type.strip() + " and is correctly setup.")
            else:
                compliant = False
                was_compliant_false = True

                latex_row = f"{latex_g.escape_latex(user)} & {latex_g.escape_latex(host)} & {latex_g.escape_latex(ssl_type)} \\\\ \\hline\n"
                latex_table += latex_row

                print("User: " + user.strip() + " has ssl_type: " + ssl_type.strip() + " and is not correctly setup!")

    if was_compliant_false is False:
        compliant = True
    elif was_compliant_false is True:
        compliant = False

    latex_table += "\\end{tabular}"
    latex_table += "\\end{center}\n"

    return {
        'compliant' : compliant,
        'config_details' : latex_table
    }


def test_insecure_auth_methods(sess):
    mysql_auth_methods = parser.parse_auth_methods(sess)
    insecure_methods = ["mysql_native_password", "mysql_old_password"]
    warning_methods = ["authentication_string"]
    secure_methods = ["caching_sha2_password", "sha256_password"]
    user_plugins_sorted = {}
    compliant = True

    for user, values in mysql_auth_methods.items():
        if not user.strip().startswith("mysql."):
            host, plugin = values

            if plugin in insecure_methods:
                user_plugins_sorted[user] = [plugin, "insecure"]
                compliant = False
            elif plugin in warning_methods:
                user_plugins_sorted[user] = [plugin, "warning"]
            elif plugin in secure_methods:
                user_plugins_sorted[user] = [plugin, "secure"]
            else:
                user_plugins_sorted[user] = [plugin, "unknown"]



    details = ""
    if bool(user_plugins_sorted):
        details = latex_g.detail_to_latex(user_plugins_sorted)
    
    return {
        'compliant' : compliant,
        'config_details' : details
    }


def test_trust_authentication(sess):
    mysql_auth_methods = parser.parse_auth_methods(sess)
    mysql_empty_passwords = parser.parse_empty_passwords(sess)
    insecure_users = {}
    compliant = True

    for user, values in mysql_auth_methods.items():
        host, plugin = values

        if plugin == "auth_socket":
            insecure_users[user] = [plugin, "insecure"]
            compliant = False

    for user, values in mysql_empty_passwords.items():
        host, plugin, auth_string = values

        insecure_users[user] = [plugin, "No password or NULL"]
        compliant = False

    details = ""
    if bool(insecure_users):
        details = latex_g.detail_to_latex(insecure_users)

    
    return {
        'compliant' : compliant,
        'config_details' : details
    }



# implementace pro User account locking. predpokladame ze na databazi neni naimplementovany custom mechanismus ale vyuziva treti stranu jako AD nebo LDAP
def test_if_uses_ldap_or_ad(sess):
    pg_hba = sess.hba_conf
    ldap_ad_methods = ["ldap", "ldaps", "saslauth", "sspi", "gss"]
    results = {}

    for key, value_list in pg_hba.items():
        database_uses_ldap_ad = False
        for entry in value_list:
            authentication_method = entry.get("authentication_method", "").lower()
            if authentication_method in ldap_ad_methods:
                database_uses_ldap_ad = True
                break
    details = ""
    if bool(results):
        details = latex_g.pg_hba_struct_to_latex(results)
    
    return {
        'compliant' : not bool(results),
        'config_details' : details
    }

def test_software_version(sess):
    installed_mysql_version = "Unknown"
    latest_mysql_version = "Unknown"

    try:
        conn = sess.conn
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION();")
        installed_mysql_version = cursor.fetchone()[0]
    except mysql.connector.Error as err:
        logger().warning("Error getting MySQL version from SQL query: {}".format(err))

        installed_mysql_version = get_mysql_version(sess.peth)

    url = "https://dev.mysql.com/downloads/mysql/"
    response = requests.get(url)
    if response.status_code == 200:
        match = re.search(r"MySQL Community Server (\d+\.\d+\.\d+)", response.text)
        if match:
            latest_mysql_version = match.group(1)
    else:
        latest_mysql_version = "9.2.0"

    logger().info("Installed MySQL version: {}".format(installed_mysql_version))
    logger().info("Latest MySQL version: {}".format(latest_mysql_version))

    is_updated = installed_mysql_version == latest_mysql_version
    details = ""
    if is_updated:
        details = "({}).".format(latest_mysql_version)
    else:
        details = "{} instead of latest version {}".format(installed_mysql_version, latest_mysql_version)

    return {
        'compliant' : is_updated,
        'config_details' : details
    }