import os
import pprint
import re
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
    db_ssl_settings = {key: value for key, value in sess.postgresql_conf.items() if key in ssl_settings_names}

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
    client_side_errors = {key: value for key, value in sess.postgresql_conf.items() if key in client_side_log_settings}
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
        details += latex_g.postgres_conf_dict_to_latex_table(client_side_errors)
    
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
    
    log_values = {key: value for key, value in sess.postgresql_conf.items() if key in recommended_values}
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
    query = "SELECT pg_read_file('postgresql.conf', 0, 1000);"
    rows1 = exec_sql_query(sess.conn, query)
    details = ""
    if rows1 != None:
        details += "\\textbf{Test was able to read postgresql.conf from SQL query}"
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
def check_postgresql_backup(backup_directory):
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
    

def check_role_permissions(sess):
    # added new structure for database privileges

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
    query = "SELECT user, host, ssl_type FROM mysql.user WHERE ssl_type != '';"
    compliant = None

    logger().info("Testing transit encryption...")

    cur.execute(query)
    result = cur.fetchall()
    cur.close()

    latex_table = ["\n "]
    latex_table.append("\\begin{center}")
    latex_table.append("\\begin{tabular}{|l|l|l|l|l|}")
    latex_table.append("\\hline")
    latex_table.append("\\textbf{USER} & \\textbf{HOST} & \\textbf{SSL_TYPE}  \\\\ \\hline")

    for row in result:
        user, host, ssl_type = row
        if not user.strip().startswith("mysql."):
            if ssl_type.strip().lower() == "x509" or ssl_type.strip().lower() == "ssl":
                print("User: " + user.strip() + " has ssl_type: " + ssl_type.strip() + " and is correctly setup.")
            else:
                compliant = False
                print("User: " + user.strip() + " has ssl_type: " + ssl_type.strip() + " and is not correctly setup!")

            if host.strip() == "%":
                host = r'\%'
            latex_row = f"{user} & {host} & {ssl_type} \\\\ \\hline"
            latex_table.append(latex_row)

    if compliant is None:
        compliant = True

    latex_table.append("\\end{tabular}")
    latex_table.append("\\end{center}")
    latex_table.append("\n")

    return {
        'compliant' : compliant,
        'config_details' : latex_table
    }


def test_insecure_auth_methods(sess):
    pg_hba = sess.hba_conf
    insecure_methods = ["trust", "password"]
    filtered_dict = {}
    for key, values in pg_hba.items():
        filtered_values = [value for value in values if value.get('authentication_method') in insecure_methods]
        if filtered_values:
            filtered_dict[key] = filtered_values

    details = ""
    if bool(filtered_dict):
        details = latex_g.pg_hba_struct_to_latex(filtered_dict)
    
    return {
        'compliant' : not bool(filtered_dict),
        'config_details' : details
    }


def test_trust_authentication(sess):
    pg_hba = sess.hba_conf
    insecure_methods = ["trust"]
    filtered_dict = {}
    for key, values in pg_hba.items():
        filtered_values = [value for value in values if value.get('authentication_method') in insecure_methods]
        if filtered_values:
            filtered_dict[key] = filtered_values
    details = ""
    if bool(filtered_dict):
        details = latex_g.pg_hba_struct_to_latex(filtered_dict)
    
    return {
        'compliant' : not bool(filtered_dict),
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
    mysql_version = get_mysql_version(sess.config_path)

    def versiontuple(v):
        return tuple(map(int, (v.split("."))))

    # zatim je tam napevno naprogramovana nejnovejsi verze. V budoucnu by tam mohl byt call ktery by bral nejnovejsi verzi z nejakeho api nebo tak
    is_updated = versiontuple(mysql_version) >= versiontuple("16.0.0")
    return {
        'compliant' : is_updated,
        'config_details' : str(mysql_version)
    }