import tests
import subprocess
import yaml
from utils.global_logger import logger
from tests import *
from utils.utils import rewrite_file
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import uuid
from utils.utils import get_mysql_version_cmd as get_mysql_version


class DocumentBuilder:
    def __init__(self, language):
        self.sev = {"info":"info", "low": "low", "medium": "medium", "high": "high"}
        self.document_builder = self.get_document_by_lang(language)
        self.yaml_data = None
        self.technical_details = None

    def get_document_builder(self):
        return self.document_builder

    def convert_dict_to_yaml(self):
        yaml_data = yaml.dump(self.get_document_builder(), default_flow_style=False) 
        self.yaml_data = yaml_data

    def generate_latex(self, args):
        self.generate_intro(args)
        self.generate_technical_details_section()
        self.generate_tested_ares_table()
        self.generate_summary()
        self.latex_to_pdf(args)
        
    def latex_to_pdf(self, args):
        engine = args.custom_latex_engine
        output_name = args.name  # Název výstupního souboru bez přípony .pdf
        logger().info(f"generating pdf from latex using {engine}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, 'latex_template')

        try:
            # Přidání přepínačů pro nastavení názvu výstupního souboru a cílové složky
            result = subprocess.run([engine, '-jobname', output_name, 'main.tex'], cwd=file_path)
            logger().info(f"Subprocess didn't except, result: {result}")
        except subprocess.CalledProcessError as e:
            logger().error(f"Could not run {engine}: ", e)
        except FileNotFoundError:
            logger().error(f"Command {engine} not found")
        except Exception as e:
            logger().error(e)


    
    def generate_summary(self):
        data = yaml.load(self.yaml_data, Loader=yaml.FullLoader)
        current_dir = os.path.dirname(os.path.abspath(__file__))


        # zajisteni ze pri multhreadingu nebude race condition
        current_dir = os.path.dirname(__file__)
        while True:
            unique_id = uuid.uuid4()
            file_name = f'severity_graph_{unique_id}.png'
            file_path = os.path.join(current_dir, f'latex_template/{file_name}')
            if not os.path.exists(file_path):
                break  

        severity_count = {'low': 0, 'medium': 0, 'high': 0, 'info': 0}
        total_count = 0
        for key, item in data.items():
            severity = item.get('severity', '').lower()
            compliant = item.get('compliant', False)
            to_be_tested = item.get('to_be_tested', '')
            if severity in severity_count and compliant == False:
                if to_be_tested:
                    severity_count[severity] += 1
                    total_count += 1

        plt.figure(figsize=(10, 6))
        plt.bar(severity_count.keys(), severity_count.values(), color=['green', 'yellow', 'red', 'blue'])
        plt.xlabel('Severity Level')
        plt.ylabel('Number of Findings')
        plt.title('Findings by Severity Level')
        plt.savefig(file_path)  

        latex = "\\section{Summary}\n"
        latex += f"""During the test total of {total_count} misconfigurations were found.
                    
                    Following figure shows graphically number of misconfigurations and their impact:
                    \n
                    """
        latex +="\\includegraphics[width=\\textwidth]{" + file_name + "}"
        rewrite_file("latex_template/summary.tex", latex)


    def generate_tested_ares_table(self):
        data = yaml.load(self.yaml_data, Loader=yaml.FullLoader)
        latex_table = """
        \\section{Tested areas}
        \\begin{center}
        \\begin{tabular}{ | m{1cm} | m{15em} | m{1.5cm} | m{1.7cm} | m{1.5cm}|}
            \\hline
            \\textbf{No.} & \\textbf{area of interest} & \\textbf{tested} & \\textbf{compliant} &\\textbf{severity}\\\\
            \\hline
        """
        for key, value in data.items():
            #print("VALS " + str(value["compliant"]) )
            tested = "$\\checkmark$" if value["to_be_tested"] else "$\\times$"
            compliant = "$\\checkmark$" if value["compliant"] else "$\\times$"
            severity = value["severity"]
            latex_table += f"    {key} & {latex_g.escape_latex(value['subsection'])} & {tested} & {compliant} & {latex_g.escape_latex(severity)} \\\\\\hline\n"

        latex_table += """
        \\end{tabular}
        \\end{center}
        """
        rewrite_file("latex_template/tested_areas.tex", latex_table)

    def generate_intro(self, identity):
        import platform
        import psutil
        import subprocess

        cpu_info = platform.processor() or "N/A"
        cpu_cores = psutil.cpu_count(logical=False)
        ram_info = psutil.virtual_memory().total // (1024**3)  
        disk_info = psutil.disk_usage('/').total // (1024**3)  
        os_info = f"{platform.system()} {platform.release()}"
        latex_preamble = f"""
            \\newpage
            \\section*{{Tested System Information}}
            \\noindent Path to MySQL Configuration: {latex_g.escape_latex(str(identity.path))} \\\\
            Database Name: {latex_g.escape_latex(str(identity.dbname))} \\\\
            User: {latex_g.escape_latex(str(identity.user))} \\\\
            Host: {latex_g.escape_latex(str(identity.host))} \\\\
            Port: {latex_g.escape_latex(str(identity.port))} \\\\
            CPU: {latex_g.escape_latex(str(cpu_info))} ({cpu_cores} cores) \\\\
            RAM: {latex_g.escape_latex(str(ram_info))} GB \\\\
            Storage Size: {latex_g.escape_latex(str(disk_info))} GB \\\\
            Operating System: {latex_g.escape_latex(str(os_info))} \\\\
            MySQL Version: {latex_g.escape_latex(get_mysql_version(identity.peth))}
                """
        rewrite_file("latex_template/intro.tex", latex_preamble)

    def generate_technical_details_section(self):
        # print(self.yaml_data)
        #data = yaml.safe_load(self.yaml_data)
        data = yaml.load(self.yaml_data, Loader=yaml.FullLoader)
        latex_code = "\\section{Technical details}\n"
        for item in data.values():
            to_be_tested = item.get('to_be_tested')
            if to_be_tested == False:
                continue
            subsection = item.get('subsection', '')
            description = item.get('description', '')
            compliant = item.get('compliant', False)
            show_config = item.get('show_config', False)
            config_details = item.get('config_details', '')
            recommendation = item.get('recommendation', '')
            
            latex_code += "\\subsection{" + latex_g.escape_latex(subsection) + "}\n"
            
            latex_code += "\\paragraph{Description} " + latex_g.escape_latex(description) + "\n\n"
            
            if compliant:
                compliant_desc = item.get('description_compliant', '')
                latex_code += latex_g.escape_latex(compliant_desc) + "\n"
                #latex_code += config_details + "\n"
            else:
                noncompliant_desc = item.get('description_noncompliant', '')
                latex_code += latex_g.escape_latex(noncompliant_desc) + "\n"
                #latex_code += config_details + "\n"
            
            # printne configuracni detaily, pokud neni compliant nebo pokud je to specificky nastavene (to je pro pripady ze je potreba 
            # ukazat konfiguraci v compliant i noncompliant pripadech)

            if show_config or compliant == False:
                #print("thru")
                latex_code += config_details + "\n"
            else:
                latex_code += "\n"
            
            if recommendation:
                latex_code += "\\paragraph{Recommendation} " + latex_g.escape_latex(recommendation) + "\n\n"
            else:
                latex_code += "\n\n"

        rewrite_file("latex_template/technical_details.tex", latex_code)
        self.technical_details = latex_code


# todo: je potreba pridat dalsi dva parametry: HOTOVO jeden bude nahrada za to be tested; bude obsahovat, ktere struktury session jsou potreba k testovani. 
                                            #   druhy bude severita nalezu
    def get_document_by_lang(self, language):
            document_data = {
                "en": {
                    1: {
                        "subsection": "Encryption at transit",
                        "description": "This test verifies that database enforces encryption to ensure safe communication that cannot be eavesdropped. "
                        "Improper configuration of encryption could lead to violation of CIA triade.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["low"],
                        "description_noncompliant": "This test found that following users are not configured to "
                                                 "ensure encrypted communication:",
                        "description_compliant": "This test found that all users enforce encrypted comunication.",
                        "config_details": "",
                        "recommendation":"We recoment implementing secure data transit with encryption.",
                        "test_function": tests.test_transit_encryption
                    },
                    2: {
                        "subsection":   "Insecure authentication methods",
                        "description":  "This test examines the configuration file 'mysql.user' for the presence of insecure "
                                        "authentication methods. Specifically, it identifies the use of 'md5' and 'password' methods, "
                                        "both of which are considered insecure. The 'md5' method employs a deprecated hash function "
                                        "that has been cryptographically compromised, while the 'password' method transmits credentials "
                                        "in plaintext, posing significant security risks.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["medium"],
                        "description_compliant": "\\textbf{Database uses configuration that enforce secure authentication methods}",
                        "description_noncompliant": "\\textbf{Database doesn't enforce secure authentication methods}",
                        "config_details": "",
                        "test_function": tests.test_insecure_auth_methods
                    },
                    3: {
                        "subsection":   "Trust authentication",
                        "description":  "Trust authentication permits unrestricted access to the database for any user without requiring a password. "
                                        "This configuration poses a significant security risk, as it allows potentially unauthorized individuals "
                                        "to gain access to sensitive data and perform unauthorized actions within the database. "
                                        "Utilizing trust authentication undermines the fundamental principle of access control and compromises "
                                        "the confidentiality, integrity, and availability of the database.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["high"],
                        "description_compliant": "\\textbf{User cannot connect without authentication.}",
                        "description_noncompliant": "\\textbf{Database allows some users to connect without password.}",
                        "config_details": "",
                        "test_function": tests.test_trust_authentication
                    },
                    4: {
                        "subsection": "Latest version of MySQL",
                        "description": "This test verifies whether the database uses the latest software version. "
                                       "Outdated versions could contain security vulnerabilities that could be used "
                                       "by an attacker to compromise the database.",
                        "compliant": False,
                        "show_config": True,
                        "required": ['db_connection'],
                        "to_be_tested": True,
                        "severity": self.sev["low"],
                        "description_compliant": "\\textbf{Database uses latest version of MySQL.}",
                        "description_noncompliant": "Database uses outdated version of MySQL: ",
                        "config_details": "",
                        "test_function": tests.test_software_version                    
                    },
                    5: {
                            "subsection":   "Permissions test",
                            "description":  "The following table provides a comprehensive overview of all privileges assigned within the specified database. "
                                            "This information is crucial for evaluating the access control mechanisms in place and identifying potential "
                                            "security vulnerabilities. A thorough permissions audit ensures that only authorized users have appropriate access "
                                            "rights, minimizing the risk of unauthorized data access or modification. "
                                            "Following table contains users and their permission on database tables:",
                            "compliant": False,
                            "show_config": True,
                            "required": ['privileges'],
                            "to_be_tested": False,
                            "severity": self.sev["info"],
                            "description_compliant": "",
                            "description_noncompliant": "",
                            "config_details": "",
                            "test_function": tests.check_role_permissions
                    },
                    6: {
                            "subsection": "Check pgcrypto",
                            "description": "Verifies whether the database is capable of encrypting its data on database layer.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": False,
                            "severity": self.sev["low"],
                            "description_compliant": "\\textbf{Database has extension pg_crypto installed.}",
                            "description_noncompliant": """Database does not implement the pg_crypto crypto extension,
                                                            be installed using the \\texttt{CREATE EXTENSION IF NOT EXISTS pgcrypto;}.""",
                            "config_details": "",
                            "test_function": tests.check_pg_crypto_extension
                    },
                    7: {
                            "subsection": "Role pg_execute_server_program enabled",
                            "description": "Verifies that no user has role that enables command execution.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": False,
                            "severity": self.sev["info"],
                            "description_compliant": "\\textbf{No users with pg\_execute\_server\_program were found.}",
                            "description_noncompliant": "Following users have the ability to execute operating system commands from SQL queries:\n",
                            "config_details": "",
                            "test_function": tests.check_if_user_has_pg_execute_server_program
                    },
                    8: {
                            "subsection": "SQL server allowed to read or write operating system files",
                            "description": "Tests whether the database is able to access OS files.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['db_connection'],
                            "to_be_tested": False,
                            "severity": self.sev["info"],
                            "description_compliant": "",
                            "description_noncompliant": "",
                            "config_details": "",
                            "test_function": tests.check_pg_file_access
                    },
                    9: {
                            "subsection": "Log configuration",
                            "description": "Verifies that the log configuration is correct.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['my.cnf'],
                            "to_be_tested": False,
                            "severity": self.sev["info"],
                            "description_compliant": "",
                            "description_noncompliant": "",
                            "config_details": "",
                            "test_function": tests.check_log_configuration
                    },
                    10: {
                            "subsection": "Client side errors",
                            "description": "Verifies that the database doesnt return errors to the client side.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['my.cnf'],
                            "to_be_tested": False,
                            "severity": self.sev["low"],
                            "description_compliant": "",
                            "description_noncompliant": "",
                            "config_details": "",
                            "test_function": tests.check_verbose_errors
                    },
                    11: {
                            "subsection": "Configuration of SSL",
                            "description": "Verifies that has the correct ssl configuration in my.cnf",
                            "compliant": False,
                            "show_config": True,
                            "required": ['my.cnf'],
                            "to_be_tested": False,
                            "severity": self.sev["medium"],
                            "description_compliant": "",
                            "description_noncompliant": "",
                            "config_details": "",
                            "test_function": tests.check_if_ssl_is_enabled
                    },
                    12: {
                            "subsection": "Unlimited superuser access",
                            "description": "This test checks superuser accounts, and verifies whether they have limited access or not.",
                            "compliant": False,
                            "show_config": True,
                            "required": ['privileges'],
                            "to_be_tested": False,
                            "severity": self.sev["info"],
                            "description_compliant": "",
                            "description_noncompliant": "",
                            "config_details": "",
                            "test_function": tests.unlimited_superuser_access
                    },
                },
            }
                

            return document_data[language]