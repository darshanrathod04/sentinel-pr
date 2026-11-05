import ast

def parse_trusted_literal(literal_str):
    result = ast.literal_eval(literal_str)
    return result
