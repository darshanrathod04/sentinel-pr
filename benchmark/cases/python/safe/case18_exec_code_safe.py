import ast

def parse_trusted_literal(user_data):
    return ast.literal_eval(user_data)
