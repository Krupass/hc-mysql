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

    logger().info("Testing transit encryption...")

    result = exec_sql_query(con, query)

    latex_table = "\\begin{center}\n\\begin{tabular}{|l|l|l|}\n\\hline\n"
    latex_table += "\\textbf{USER} & \\textbf{HOST} & \\textbf{SSL\\_TYPE} \\\\ \\hline\n"

    for row in result:
        user, host, ssl_type = row
        if not user.strip().startswith("mysql."):
            if ssl_type.strip().lower() == "x509" or ssl_type.strip().lower() == "ssl" or ssl_type.strip().lower() == "any":
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
        details = latex_g.detail_to_latex(user_plugins_sorted, "User", "Host", "Plugin")
    
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
        details = latex_g.detail_to_latex(insecure_users, "User", "Plugin", "Password")

    
    return {
        'compliant' : compliant,
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
        'config_details' : "\\textbf{ " + details + "}"
    }

def test_user_permissions(sess):
    return {
        'compliant': False,
        'config_details': latex_g.privilege_dict_to_latex_table(sess.privileges)
    }

def test_loadable_functions(sess):
    return {
        'compliant': "",
        'config_details': ""
    }

def test_file_access(sess):
    compliant = False
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

        details = details + "\n" + latex_g.detail_to_latex(parsed_data, "User", "Host", "File_priv")

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_log_conf(sess):
    return {
        'compliant': "",
        'config_details': ""
    }

def test_verbose_errors(sess):
    compliant = False
    details = ""
    con = sess.conn
    query = """SHOW VARIABLES LIKE 'log_error_verbosity';"""

    result =  exec_sql_query(con, query)

    variable, value = result[0]

    if variable == "log_error_verbosity":
        if value == "1":
            compliant = True
            details = "\\textbf{Current level of error verbosity is 1, which is recommended setting.}"
        elif value == "2":
            compliant = False
            details = ("\\textbf{Current level of error verbosity is 2, which isn't recommended setting. "
                       "Warnings are logged, consider reducing verbosity}")
        elif value == "3":
            compliant = False
            details = ("\\textbf{Current level of error verbosity is 3, which is insecure setting. "
                       "Detailed logs could expose sensitive information}")
        else:
            logger().warning("Unknown log_error_verbosity value: {}".format(value))
    else:
        logger().warning("Unknown variable in verbose errors testing: {}".format(variable))

    return {
        'compliant': compliant,
        'config_details': details
    }

def test_ssl(sess):
    compliant = False
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

        details = latex_g.detail_to_latex(parsed_data, "User", "Host", "SUPER")
        compliant = False
    else:
        compliant = True
        details = ""

    return {
        'compliant': compliant,
        'config_details': details
    }