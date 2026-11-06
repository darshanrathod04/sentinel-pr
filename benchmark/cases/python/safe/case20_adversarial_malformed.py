# Benign complex code with nested list comprehensions and clean math
def process_matrix(matrix):
    transformed = [
        [val * 2 for val in row if val > 0]
        for row in matrix
    ]
    return transformed
