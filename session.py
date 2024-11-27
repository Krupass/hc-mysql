from logging import exception, error
from pathlib import Path
import os
import configparser
import mysql.connector
from document_builder import DocumentBuilder
from utils.global_logger import logger
from utils.utils import convert_dict_to_yaml
from tests import check_pg_crypto_extension
from utils.errors import InvalidPgHbaConfigFormat
from utils.utils import exec_sql_query
from utils.utils import sub_array
from utils.utils import build_connect_string
import utils.parsers as parse
import pprint
from experimental_db_setup import setup_database


class Session():
    def __init__(self, args):
        self.config_path = args.path
        self.resources = []
        self.conn = None
        self.my_conf = None
        self.privileges = None
        self.document_builder = DocumentBuilder(args.language)
        if args.setup_db == True:
            db_name = "experimental_db"
            setup_database(args, db_name)

        if args.name == None:
            args.name = "{}-{}_{}".format(args.dbname, args.host, args.port)

        try:
            self.conn = mysql.connector.connect(**build_connect_string(args))
            logger().info(f"connection established successfully, connection details: {self.conn}")
            self.resources.append('db_connection')
        except mysql.connector.Error as e:
            logger().warning(f"Error: {e}")
            #vynechat testy ktere potrebuji pripojeni k databazi

        my_conf_path = os.path.join(self.config_path, "my.ini")
        # todo zjistit co z pg_hba.conf a postgresql.conf je v souboru my.ini a co v uživatelske tabulce mysql.user
        # hba_conf_path = os.path.join(self.config_path, "pg_hba.conf")
        # postgresql_conf_path = os.path.join(self.config_path, "postgresql.conf")

        try:
            with open(my_conf_path, "r", encoding="utf-8") as file:
                content = file.read()
                file.close()

            self.my_conf = {}

            group = None
            for line in content.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    if line.strip().startswith("["):
                        group = line.strip()[1:-1]
                    if "=" in line:
                        key, value = line.split("=", 1)
                        if group is None:
                            self.my_conf[key.strip()] = value.strip()
                        else:
                            key = f"{group}_{key.strip()}"
                            self.my_conf[key] = value.strip()


            # for key, value in self.my_conf.items():
            #     print(f"{key}: {value}")

            logger().info("my.ini configuration file successfully loaded.")
            self.resources.append('my.ini')

        except FileNotFoundError:
            logger().warning(f"config file not found: {my_conf_path}")

        # parse pg hba conf
        # try:
        #     self.hba_conf = parse.parse_pg_hba_config(self, hba_conf_path)
        #     logger().info("pg_hba.conf successfully parsed.")
        #     self.resources.append('pg_hba.conf')
        # except:
        #     logger().warning("pg_hba.conf couldn't be parsed.")
        
        # parse postgresql try:
        # try:
        #     self.postgresql_conf = parse.parse_postgresql_conf(self, postgresql_conf_path)
        #     logger().info("postgresql.conf successfully parsed.")
        #     self.resources.append('postgresql.conf')
        # except:
        #     logger().warning("postgresql.conf couldn't be parsed.")


        # parse database privileges
        try:
            if self.conn != None:
                self.privileges = parse.parse_database_privileges(self)
            if not bool(self.privileges):
                logger().warning("error while parsing database privileges")
            else:
                self.resources.append('privileges')
                logger().info("succesfully parsed database privileges")
        except e:
                logger().warning(f"error while parsing database privileges {e}")

        # urcit jake testy jsou mozne provest, asi bude potreba pridat nejake flagy do document builder testove struktury. 
        self.test_master()
        self.document_builder.convert_dict_to_yaml()
        if not args.no_report:
            logger().info(f"PDF generating skipped")
        else:
            self.document_builder.generate_latex(args)

        if self.conn != None:
            self.conn.close()

    def test_master(self):
        for number, data in self.document_builder.get_document_builder().items():
            if not sub_array(self.resources, data["required"]):
                data['to_be_tested'] = False
            if data['to_be_tested'] == False:
                continue
            output = data['test_function'](self)
            logger().info(f"ran test function: {data['test_function'].__name__} with output: {output}")
            if output['compliant'] == False:
                data['config_details'] = str(output['config_details'])
            data['compliant'] = output['compliant']

