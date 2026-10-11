import re, sys
# usage: swap_test_func.py TARGET_FILE SOURCE_FILE FUNC  -- заменяет функцию (с примыкающим блоком // комментариев) целиком
def block(text, name):
    m = re.search(r'((?:^//[^\n]*\n)*)^func %s\(.*?^}\n' % re.escape(name), text, re.S | re.M)
    if not m: sys.exit('func %s not found' % name)
    return m
tgt, src, name = sys.argv[1:4]
t = open(tgt, encoding='utf-8').read(); s = open(src, encoding='utf-8').read()
mt, ms = block(t, name), block(s, name)
open(tgt, 'w', encoding='utf-8').write(t[:mt.start()] + ms.group(0) + t[mt.end():])
print('swapped', name, 'in', tgt)
