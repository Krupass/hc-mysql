import pprint
import re
import latex_generator as latex_g



def mysql_conf_dict_to_latex_table(data):
    latex_table = "\\begin{center}\n\\begin{tabular}{|l|l|}\n\\hline\n"
    latex_table += "\\textbf{Parameter} & \\textbf{Value} \\\\\n\\hline\n"

    for key, value in data.items():
        key = escape_latex(key)
        if isinstance(value, str):
            value = escape_latex(value)
            value = f"\\texttt{{{value}}}"

        latex_table += f"{key} & {value} \\\\\n\\hline\n"

    latex_table += "\\end{tabular}\n\\end{center}"

    return latex_table

def privilege_dict_to_latex_table(privilege_dict):
    latex_table = "\\begin{tabular}{|l|l|l|l|}\n\\hline\n"
    latex_table += "\\textbf{User Type} & \\textbf{Table Schema} & \\textbf{Table Name} & \\textbf{Privilege Types} \\\\\n\\hline\n"
    
    for user_type, privileges in privilege_dict.items():
        for privilege in privileges:
            privileges_str = ', '.join(privilege['privilege_type'])
            latex_table += f"{latex_g.escape_latex(user_type)} & {latex_g.escape_latex(privilege['table_schema'])} & {latex_g.escape_latex(privilege['table_name'])} & {latex_g.escape_latex(privileges_str)} \\\\\n"
            latex_table += "\\hline\n"

    latex_table += "\\end{tabular}"
    return latex_table

def detail_to_latex(sorted_dict):
    latex_table = ["\\begin{center}"]
    latex_table.append("\\begin{tabular}{|l|l|l|}")
    latex_table.append("\\hline")
    latex_table.append("\\textbf{User} & \\textbf{Plugin} & \\textbf{Security} \\\\ \\hline")
    for user, values in sorted_dict.items():
        plugin, security = values
        latex_row = f"{escape_latex(user)} & {escape_latex(plugin)} & {escape_latex(security)} \\\\ \\hline"
        latex_table.append(latex_row)
    
    latex_table.append("\\end{tabular}")
    latex_table.append("\\end{center}")
    return "\n".join(latex_table)

def lstlisting(input_text):
    output = ["\\begin{lstlisting}"]
    output.append(input_text)
    output.append("\\end{lstlisting}")
    return "\n".join(output)

def escape_latex(s):
    allowed_tags = ['texttt', 'url', 'textbf']
    tag_pattern = r'(\\(?:' + '|'.join(allowed_tags) + r'){(?:[^{}]|{[^}]*})*})' 

    def escape_special_chars(text):
        replacements = {
            '&':  r'\&',
            '{':  r'\{',
            '}':  r'\}',
            '%':  r'\%',
            '$':  r'\$',
            '#':  r'\#',
            '_':  r'\_',
            '~':  r'\textasciitilde{}',
            '^':  r'\textasciicircum{}',
            '\\': r'\textbackslash{}',
            '<':  r'\textless{}',
            '>':  r'\textgreater{}',
            '\u2018': "'",  
            '\u2019': "'",  
            '\u201C': '"',  
            '\u201D': '"',
        }
        return ''.join(replacements.get(c, c) for c in text)
    segments = re.split(tag_pattern, s)

    escaped_segments = [escape_special_chars(segment) if not re.match(tag_pattern, segment) else segment for segment in segments]

    return ''.join(escaped_segments)

