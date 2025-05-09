import os
import pprint
import re
import mysql.connector
import requests

from latex_generator import escape_latex
from utils.global_logger import logger
from utils.utils import exec_sql_query
from utils.utils import get_mysql_version_cmd as get_mysql_version
import utils.parsers as parser
import latex_generator as latex_g

def test_transit_encryption(sess):
    con = sess.conn
    query = "SELECT user, host, ssl_type FROM mysql.user;"
    compliant = None
    was_compliant_false = False
    details = ""

    result = exec_sql_query(con, query)

    parsed_data = {}

    for row in result:
        user, host, ssl_type = row
        if not user.strip().startswith("mysql."):
            if ssl_type.strip().lower() == "x509" or ssl_type.strip().lower() == "ssl" or ssl_type.strip().lower() == "any":
                compliant = True
            else:
                compliant = False
                was_compliant_false = True
                if ssl_type.strip() == "":
                    parsed_data[user] = [host, "$\\times$"]
                else:
                    parsed_data[user] = [host, ssl_type]

    if not parsed_data == {}:
        details = latex_g.detail_to_latex(parsed_data, "User", "Host", "SSL Type", False) + "\n"

    parsed_data = {}

    require_secure_transport = sess.my_conf.get("mysqld_require_secure_transport", None)
    if require_secure_transport is None:
        query = """SHOW VARIABLES LIKE 'require_secure_transport';"""
        result = exec_sql_query(con, query)
        variable, require_secure_transport = result[0]

    parsed_data["require_secure_transport"] = require_secure_transport
    require_secure_transport = require_secure_transport.strip().lower()

    if require_secure_transport == "on":
        compliant = True
        details = details + "Clients are required to use some form of secure transport. "
    elif require_secure_transport == "off":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{Clients aren't required to use form of secure transport. } "
    else:
        logger().warning("Require secure transport untracked value: {}.".format(require_secure_transport))

    ssl_cipher = sess.my_conf.get("mysqld_ssl_cipher", None)
    if ssl_cipher is None:
        query = """SHOW VARIABLES LIKE 'ssl_cipher';"""
        result = exec_sql_query(con, query)
        variable, ssl_cipher = result[0]

    if ssl_cipher.strip() == "":
        parsed_data["ssl_cipher"] = "$\\times$"
    else:
        parsed_data["ssl_cipher"] = ssl_cipher.strip()
    ssl_cipher = ssl_cipher.strip().lower()

    if ssl_cipher == "none" or ssl_cipher is None or ssl_cipher == "null" or ssl_cipher == "":
        compliant = False
        was_compliant_false = True
        details = details + "\\textbf{No SSL encryption cipher specified. } "
    else:
        compliant = True
        details = details + "List of permissible encryption ciphers specified. "

    if was_compliant_false is True:
        compliant = False

    details = details + "\n" + latex_g.mysql_conf_dict_to_latex_table(parsed_data, "Variable", "Value", False)

    return {
        'compliant' : compliant,
        'config_details' : details
    }

def test_rest_encryption(sess):
    con = sess.conn
    query = """SELECT NAME, SPACE_TYPE, ENCRYPTION 
                FROM INFORMATION_SCHEMA.INNODB_TABLESPACES"""
    compliant = None
    was_compliant_false = False

    result = exec_sql_query(con, query)
    parsed_data = {}

    for row in result:
        name, space_type, encryption = row
        if encryption.strip().lower() == "y":
            compliant = True
        else:
            compliant = False
            was_compliant_false = True

        parsed_data[name] = [space_type, encryption]

    if was_compliant_false is True:
        compliant = False

    return {
        'compliant' : compliant,
        'config_details' : latex_g.detail_to_latex(parsed_data, "Name", "Space Type", "Encryption", True)
    }


def test_insecure_auth_methods(sess):
    mysql_auth_methods = parser.parse_auth_methods(sess)
    insecure_methods = ["mysql_native_password", "mysql_old_password"]
    warning_methods = []
    secure_methods = ["caching_sha2_password", "sha256_password"]
    user_plugins_sorted = {}
    compliant = None
    was_false = False

    for user, values in mysql_auth_methods.items():
        if not user.strip().startswith("mysql."):
            host, plugin = values

            if plugin in insecure_methods:
                user_plugins_sorted[user] = [plugin, "insecure"]
                compliant = False
                was_false = True
            elif plugin in warning_methods:
                user_plugins_sorted[user] = [plugin, "warning"]
            elif plugin in secure_methods:
                user_plugins_sorted[user] = [plugin, "secure"]
                compliant = True
            else:
                user_plugins_sorted[user] = [plugin, "unknown"]
                compliant = False
                was_false = True



    details = ""
    if bool(user_plugins_sorted):
        details = latex_g.detail_to_latex(user_plugins_sorted, "User", "Plugin", "Security", True)

    if was_false is True:
        compliant = False

    return {
        'compliant' : compliant,
        'config_details' : details
    }


def test_trust_authentication(sess):
    mysql_auth_methods = parser.parse_auth_methods(sess)
    mysql_empty_passwords = parser.parse_empty_passwords(sess)
    insecure_users = {}
    compliant = None

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
        details = details + "\n" + latex_g.detail_to_latex(insecure_users, "User", "Plugin", "Password", True)

    
    return {
        'compliant' : compliant,
        'config_details' : details
    }

def test_software_version(sess):
    installed_mysql_version = "Unknown"
    latest_mysql_version = "Unknown"

    try:
        con = sess.conn
        query = "SELECT VERSION();"
        result = exec_sql_query(con, query)
        installed_mysql_version = result[0]
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

    logger().info("Installed MySQL version: {}".format(installed_mysql_version[0]))
    logger().info("Latest MySQL version: {}".format(latest_mysql_version))

    is_updated = installed_mysql_version[0] == latest_mysql_version
    details = ""
    if is_updated:
        details = "({}).".format(latest_mysql_version)
    else:
        details = "{} instead of latest version {}".format(installed_mysql_version[0], latest_mysql_version)

    return {
        'compliant' : is_updated,
        'config_details' : "\\textbf{ " + details + "}"
    }

def test_user_permissions(sess):
    return {
        'compliant': False,
        'config_details': latex_g.privilege_dict_to_latex_table(sess.privileges)
    }

def test_loadable_functions(sess):
    compliant = None
    details = ""
    con = sess.conn

    parsed_data = {}

    local_infile = sess.my_conf.get("mysqld_local_infile", None)
    if local_infile is None:
        query = """SHOW VARIABLES LIKE 'local_infile';"""
        result = exec_sql_query(con, query)
        variable, local_infile = result[0]

    local_infile = local_infile.strip().lower()

    if local_infile == "on":
        compliant = False
        details = details + "\\textbf{Clients can load functions by \\texttt{LOAD DATA} statements.} "
    elif local_infile == "off":
        compliant = True
        details = details + "Clients can't use \\texttt{LOAD DATA} statements. "
    else:
        logger().warning("Local infile untracked value: {}.".format(local_infile))

    query = """SELECT * FROM mysql.func;"""
    result = exec_sql_query(con, query)

    if result:
        latex_table = ["\\begin{center}"]
        latex_table.append("\\begin{tabular}{|l|c|c|c|}")
        latex_table.append("\\hline")
        latex_table.append("\\textbf{Name} & \\textbf{Ret} & \\textbf{Dll} & \\textbf{Type} \\\\ \\hline")

        for row in result:
            name, ret, dll, type = row
            latex_row = f"{escape_latex(name)} & {escape_latex(ret)} & {escape_latex(dll)} & {escape_latex(type)} \\\\ \\hline"
            latex_table.append(latex_row)

        latex_table.append("\\end{tabular}")
        latex_table.append("\\end{center}")
        details = details + "\\textbf{Check if all function in mysql.func table are necessary.}" + "\n".join(latex_table)
        compliant = False
    else:
        details = details + "No functions in mysql.func table."

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_file_access(sess):
    compliant = None
    details = ""
    con = sess.conn
    query = """SELECT @@global.secure_file_priv;"""

    directory = exec_sql_query(con, query)

    if directory[0][0] == "":
        logger().warning("Unrestricted write/read access to files.")
        compliant = False
        details = "\\textbf{SQL server has unrestricted write/read access to files.}"
    elif directory[0][0] == "NULL" or None:
        logger().info("No access to files.")
        compliant = True
        details = "SQL server has no access to files."
    else:
        logger().info("Access to files in directory: {}".format(directory[0][0]))
        compliant = True
        details = "SQL server has access to files in directory {}.".format(latex_g.escape_latex(directory[0][0]))


    query = """SELECT User, Host, File_priv
                   FROM mysql.user
                   WHERE File_priv = 'Y';"""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result == "":
        details = details + " No user has privilege to read/write to files."
    else:
        details = details + " Users in following table have privilege to read/write to files."
        for user, host, file_priv in result:
            if user not in parsed_data:
                parsed_data[user] = [host, file_priv]

        details = details + "\n" + latex_g.detail_to_latex(parsed_data, "User", "Host", "File_priv", True)

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_log_conf(sess):
    compliant = None
    wasFalse = False
    details = ""
    con = sess.conn

    parsed_data = {}

    general_log = sess.my_conf.get("mysqld_general_log", None)
    if general_log is None:
        query = """SHOW VARIABLES LIKE 'general_log';"""
        result = exec_sql_query(con, query)
        variable, general_log = result[0]

    parsed_data["general_log"] = general_log
    general_log = general_log.strip().lower()

    if general_log == "on":
        compliant = True
        details = details + "General logging is on. "
    elif general_log == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{General logging is off.} "
    else:
        logger().warning("General logging untracked value: {}.".format(general_log))

    log_raw = sess.my_conf.get("mysqld_log_raw", None)
    if log_raw is None:
        query = """SHOW VARIABLES LIKE 'log_raw';"""
        result = exec_sql_query(con, query)
        variable, log_raw = result[0]

    parsed_data["log_raw"] = log_raw
    log_raw = log_raw.strip().lower()

    if log_raw == "on":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Passwords can be exposed because of the log\\_raw setting.} "
    elif log_raw == "off":
        compliant = True
        details = details + "Log\\_raw setting doesn't expose passwords. "
    else:
        logger().warning("Log\\_raw setting untracked value: {}.".format(log_raw))

    slow_query_log = sess.my_conf.get("mysqld_slow_query_log", None)
    if slow_query_log is None:
        query = """SHOW VARIABLES LIKE 'slow_query_log';"""
        result = exec_sql_query(con, query)
        variable, slow_query_log = result[0]

    parsed_data["slow_query_log"] = slow_query_log
    slow_query_log = slow_query_log.strip().lower()

    if slow_query_log == "on":
        compliant = True
        details = details + "Slow query logging is on. "
    elif slow_query_log == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Slow query logging is off.} "
    else:
        logger().warning("Slow query logging untracked value: {}".format(slow_query_log))

    long_query_time = sess.my_conf.get("mysqld_long_query_time", None)
    if long_query_time is None:
        query = """SHOW VARIABLES LIKE 'long_query_time';"""
        result = exec_sql_query(con, query)
        variable, long_query_time = result[0]

    parsed_data["long_query_time"] = float(long_query_time).__round__(1)

    if float(long_query_time) > 10:
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Long query time is too long.} "
    else:
        compliant = True
        details = details + "Long query time is set reasonably. "

    innodb_strict_mode = sess.my_conf.get("mysqld_innodb_strict_mode", None)
    if innodb_strict_mode is None:
        query = """SHOW VARIABLES LIKE 'innodb_strict_mode';"""
        result = exec_sql_query(con, query)
        variable, innodb_strict_mode = result[0]

    parsed_data["innodb_strict_mode"] = innodb_strict_mode
    innodb_strict_mode = innodb_strict_mode.strip().lower()

    if innodb_strict_mode == "on":
        compliant = True
        details = details + "Innodb strict logging is on."
    elif innodb_strict_mode == "off":
        compliant = False
        wasFalse = True
        details = details + "\\textbf{Innodb strict logging is off.}"
    else:
        logger().warning("InnoDB strict logging untracked value: {}".format(innodb_strict_mode))

    if wasFalse == True:
        compliant = False

    return {
        'compliant': compliant,
        'config_details': details + "\n" + latex_g.mysql_conf_dict_to_latex_table(parsed_data, "Variable", "Value", True),
    }

def test_ssl(sess):
    compliant = None
    con = sess.conn
    query = """SHOW VARIABLES 
                LIKE 'have_ssl';"""

    result = exec_sql_query(con, query)

    variable, value = result[0]

    if variable == 'have_ssl':
        if value == 'YES':
            details = "SSL is allowed."
            compliant = True
        else:
            details = "SSL isn't active."
            compliant = False
    else:
        details = ""
        logger().warning("Variable 'have_ssl' not found.")

    query = """SHOW VARIABLES
                WHERE Variable_name 
                IN ('ssl_ca', 'ssl_cert', 'ssl_key');"""

    result = exec_sql_query(con, query)

    latex_table = "\\begin{center}\n\\begin{tabular}{|l|l|}\n\\hline\n"
    latex_table += "\\textbf{Variable name} & \\textbf{Value} \\\\ \\hline\n"

    for variable, value in result:
        if variable == 'ssl_ca':
            if value == '' or value == 'NULL':
                details = details + (" SSL Certificate Authority (CA) is missing or not configured. "
                                     "MySQL will not validate client certificates, which may reduce security.")
                if compliant:
                    compliant = False
            else:
                details = details + (" SSL Certificate Authority (CA) is correctly configured. "
                                     "MySQL can verify client certificates.")
        elif variable == 'ssl_cert':
            if value == '' or value == 'NULL':
                details = details + (" SSL certificate is missing or not configured. "
                                     "MySQL cannot establish encrypted connections.")
                if compliant:
                    compliant = False
            else:
                details = details + " SSL certificate is correctly set."
        elif variable == 'ssl_key':
            if value == '' or value == 'NULL':
                details = details + (" SSL private key is missing or not configured. "
                                     "MySQL cannot use SSL for encrypted connections.")
                if compliant:
                    compliant = False
            else:
                details = details + " SSL private key is correctly set."

        latex_row = f"{latex_g.escape_latex(variable)} & {latex_g.escape_latex(value)} \\\\ \\hline\n"
        latex_table += latex_row

    latex_table += "\\end{tabular}"
    latex_table += "\\end{center}\n"

    details = details + "\n" + latex_table

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_super(sess):
    con = sess.conn
    query = """SELECT User, Host, Super_priv
               FROM mysql.user
               WHERE Super_priv = 'Y';"""

    result = exec_sql_query(con, query)
    parsed_data = {}

    if result:
        for user, host, super_priv in result:
            if user not in parsed_data:
                parsed_data[user] = [host, super_priv]

        details = latex_g.detail_to_latex(parsed_data, "User", "Host", "SUPER", True)
        compliant = False
    else:
        compliant = True
        details = ""

    return {
        'compliant': compliant,
        'config_details': details
    }