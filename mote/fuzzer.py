import random
import string


SAMPLE_SIZE = 20

def get_boolean():
    sample = ['true', 'false']
    return random.choices(sample)[0]


def get_float():
    return "{0:.2f}".format(random.uniform(0, 1))


# def get_string():
#     length = random.randint(1, SAMPLE_SIZE)
#     return repr(''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length)))

def get_string(base_string):
    """
    Generate a string by randomly mutating the given base string.
    The length of the mutated string will be the same as the base string.
    """
    mutated_string = list(base_string)
    for i in range(len(mutated_string)):
        if random.random() < 0.5:  # 50%的概率变异每个字符
            mutated_string[i] = random.choice(string.ascii_letters + string.digits + string.punctuation)
    return ''.join(mutated_string)


def get_fuction():
    return "(res) => {{ console.log('self-defined function called', res)}}"


def get_hexcolor():
    color = ''.join(random.choices(string.hexdigits, k=6))
    color = '#' + color
    return repr(color)


def get_integer():
    return repr(random.randint(-9007199254740991, 9007199254740991)) # Number.MAX_SAFE_INTEGER


def get_string_array():
    
    ret = "["
    ret += get_string() + ","
    ret += get_string()
    ret += "]"
    
    # return "new ArrayBuffer(16)"
    return ret

def get_boolean_list():
    ret = list()
    for i in range(SAMPLE_SIZE):
        ret.append(get_boolean())
    return ret


def get_float_list():
    ret = list()
    for i in range(SAMPLE_SIZE):
        ret.append(get_float())
    return ret


# def get_string_list():
#     ret = list()
#     for i in range(SAMPLE_SIZE):
#         ret.append(get_string())
#     return ret

def get_string_list(base_string):
    """
    Generate a list of mutated strings based on the base string.
    """
    ret = []
    for i in range(SAMPLE_SIZE):
        ret.append(get_string(base_string))
    return ret

def get_fuction_list():
    ret = list()
    for i in range(SAMPLE_SIZE):
        ret.append(get_fuction())
    return ret


def get_hexcolor_list():
    ret = list()
    for i in range(SAMPLE_SIZE):
        ret.append(get_hexcolor())
    return ret


def get_integer_list():
    ret = list()
    for i in range(SAMPLE_SIZE):
        ret.append(get_integer())
    return ret


def get_string_array_list():
    ret = list()
    for i in range(SAMPLE_SIZE):
        ret.append(get_string_array())
    return ret

