import hashlib, re


def hex_to_b58check(inp, magicbyte=0):
    return bin_to_b58check(inp.decode('hex'), magicbyte)


def bin_to_b58check(inp, magicbyte=0):
    inp_fmtd = chr(int(magicbyte)) + inp
    leadingzbytes = len(re.match('^\x00*', inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd + checksum, 256, 58)


def bin_dbl_sha256(string):
    return hashlib.sha256(hashlib.sha256(string).digest()).digest()


def changebase(string, frm, to, minlen=0):
    return encode(decode(string, frm), to, minlen)


def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result = ""
    while val > 0:
        result = code_string[val % base] + result
        val /= base
    if len(result) < minlen:
        result = code_string[0] * (minlen - len(result)) + result
    return result


def decode(string, base):
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 16: string = string.lower()
    while len(string) > 0:
        result *= base
        result += code_string.find(string[0])
        string = string[1:]
    return result


def get_code_string(base):
    if base == 2:
        return '01'
    elif base == 10:
        return '0123456789'
    elif base == 16:
        return "0123456789abcdef"
    elif base == 58:
        return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    elif base == 256:
        return ''.join([chr(x) for x in range(256)])
    else:
        raise ValueError("Invalid base!")


if __name__ == '__main__':

    eth_address = "9c9de44724a4054da0eaa605abcc802668778bea"
    print("%s -> %s :" % ("eth_address","btc_address"))
    print("%s -> %s" % (eth_address, hex_to_b58check(eth_address)))
