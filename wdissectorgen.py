#!/usr/bin/env python
# coding: utf-8

"""
Wireshark Dissector Generator(WDissectorGen)
This file is part of Wireshark Dissector Generator(WDissectorGen).
Wireshark Dissector Generator(WDissectorGen) is free software: 
you can redistribute it and/or modify it under the terms of the 
GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.
Wireshark Dissector Generator(WDissectorGen) is distributed in the hope 
that it will be useful,but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with Wireshark Dissector Generator(WDissectorGen).  
If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import yaml
from datetime import date
import yamale

__version__ = '0.1'
__author__ = 'Antonio Blescia'

code_template_file_content = ""
yaml_template_file_content = ""
yaml_deserialized_object = None

def load_file_content(filename):
    """
    Loads the file content

    :param filename: the file path
    :return: The content of the file
    """
    content = ""
    with open(filename, 'r') as stream:
        try:
            content = stream.read()
        except:
            pass
    return content

def compose_fields_declaration():
    """
    Composes the string with the fields declaration

    :return: The fields declaration string
    """
    fields = []
    field_declaration_format = "{0}_field=ProtoField.{1}(\"{2}\",\"{3}\",base.{4})"    
    for field in yaml_deserialized_object['fields']:
        fields.append(field_declaration_format.format(field['name'],\
                                                     field['type'],
                                                     field['filter'],
                                                     field['short_description'],
                                                     field['base']))
    return "\n".join(fields)

def compose_fields_list():
    """
    Composes the string with the fields list declaration

    :return: The fields list declaration string
    """
    fields = []
    field_declaration_format = "{0}_field"
    for field in yaml_deserialized_object['fields']:
        fields.append(field_declaration_format.format(field['name']))
    
    return ",\n".join(fields)

def compose_local_variable_declaration():
    """
    Composes the string with the local variables declaration

    :return: The local variables declaration
    """
    local_variables=[]
    local_declaration_variable_format="local {0} = buffer({1},{2})"
    for field in yaml_deserialized_object['fields']:
        local_variables.append(local_declaration_variable_format.format(field['name'], \
                                                                        field['offset'],
                                                                        field['size']))
    return "\n".join(local_variables)

def compose_subtree_tree():
    """
    Composes the string with the subtree population declaration

    :return: The subtree population declaration string
    """
    subtree_elements=[]
    add_element_to_subtree_format="subtree:add({0}_field, {1})"
    add_element_to_subtree_format_with_function="subtree:add({0}_field, {1}):append_text(\"[{2}():\".. {3}({4})..\"]\")"
    for field in yaml_deserialized_object['fields']:
        try:
            subtree_elements.append(add_element_to_subtree_format_with_function.format(field['name'], \
                                                                                       field['name'], \
                                                                                       field['function_name'], \
                                                                                       field['function_name'], \
                                                                                       field['name']))
        except:
            subtree_elements.append(add_element_to_subtree_format.format(field['name'], \
                                                                         field['name']))
    return "\n".join(subtree_elements)

def compose_dissector_ports():
    """LOCAL_VAR_DECLARATION
    Composes the string with the ports declaration 

    :return: The port declaration
    """
    ports=[]
    ports_format="{0}_port:add({1}, {2})"
    for port in yaml_deserialized_object['connection']['ports']:
        ports.append(ports_format.format(str(yaml_deserialized_object['connection']['type']),\
                                         str(port),
                                         str(yaml_deserialized_object['protocol']['name'])))
    return "\n".join(ports)
    
def write_custom_function():
    """
    Composes the string with the custom function declaration

    :return: The custom functions declaration
    """
    functions=[]
    for field in yaml_deserialized_object['fields']:
        try:
            functions.append(field['function'])
        except KeyError:
            pass
    return "\n".join(functions)

def compose_lua_source_code():
    global code_template_file_content

    # Updates the %DATE%
    code_template_file_content = code_template_file_content.replace("%DATE%",str(date.today()))
    # Updates the %PROTOCOL_NAME%
    code_template_file_content = code_template_file_content.replace("%PROTOCOL_NAME%", str(yaml_deserialized_object['protocol']['name']))
    # Updates the %PROTOCOL_DESCRIPTION%
    code_template_file_content = code_template_file_content.replace("%PROTOCOL_DESCRIPTION%", str(yaml_deserialized_object['protocol']['name']))
    # Updates the %FIELDS_DECLARATION%
    code_template_file_content = code_template_file_content.replace("%FIELDS_DECLARATION%", compose_fields_declaration())
    # Updates the %FIELDS_LIST%
    code_template_file_content = code_template_file_content.replace("%FIELDS_LIST%", compose_fields_list())
    # Updates the %LOCAL_VAR_DECLARATION%
    code_template_file_content = code_template_file_content.replace("%LOCAL_VAR_DECLARATION%", compose_local_variable_declaration())
    # Updates the %SUBTREE_POPULATION%
    code_template_file_content = code_template_file_content.replace("%SUBTREE_POPULATION%", compose_subtree_tree())
    # Updates the %CUSTOM_FUNCTIONS%
    code_template_file_content = code_template_file_content.replace("%CUSTOM_FUNCTIONS%", write_custom_function())
    # Updates the %PROTOCOL%
    code_template_file_content = code_template_file_content.replace("%PROTOCOL%", str(yaml_deserialized_object['connection']['type']))
    # Updates the %PORTS%
    code_template_file_content = code_template_file_content.replace("%PORTS%", compose_dissector_ports())
    

def write_lua_source():
    """
    Writes the LUA source code dissector

    :return: None
    """
    lua_source = open("{0}.lua".format(yaml_deserialized_object['protocol']['name']), "w")
    lua_source.write(code_template_file_content)
    lua_source.close()

def validate_yaml_protocol_description_file():
    is_valid = False
    schema = yamale.make_schema(sys.argv[2])
    data = yamale.make_data(sys.argv[1])
    try:
        yamale.validate(schema, data)
        is_valid = True
    except Exception as ex:
        print ex
    return is_valid
    
if __name__ == "__main__":

    code_template_file_content = load_file_content("code_template")
    yaml_template_file_content = load_file_content(sys.argv[1])
    
    
    if validate_yaml_protocol_description_file() == True:
        yaml_deserialized_object = yaml.load(yaml_template_file_content)
        compose_lua_source_code()
        write_lua_source()
