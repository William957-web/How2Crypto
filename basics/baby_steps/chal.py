from flags import flag1 as flag

lowers = "abcdefghijklmnopqrstuvwxyz"
uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def caeser(s, key):
    result = ""
    for c in s:
        if c in lowers:
            result += lowers[(lowers.index(c)+key)%26]
        elif c in uppers:
            result += uppers[(uppers.index(c)+key)%26]
        else:
            result += c
    return result

def affine(s, a, b):
    result = ""
    for c in s:
        if c in lowers:
            result += lowers[(lowers.index(c)*a+b)%26]
        elif c in uppers:
            result += uppers[(uppers.index(c)*a+b)%26]
        else:
            result += c
    return result

l=len(flag)//2

print(caeser(flag[:l], 3)+affine(flag[l:], 7, 11))

### output ###
# IODJ{E4eb_V7hSh_Bp@yo_ho3mh!}