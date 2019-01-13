import sys, re

def convert (json_file):
    with open(json_file, 'r') as f:
        data = []
        for line in f:
            splitted = re.compile('\s+').split(line.rstrip('\n'))
            name = splitted[1]
            code = int(splitted[0], 0)
            klass = code & 0xff000000
            if klass == 0xff000000: # MIG
                name = name.replace('MSG_', '')
            data.append((splitted[0], name))

        print '/* generated file, do not edit */\n'
        print '#ifndef R_TRACE_CODES_H'
        print '#define R_TRACE_CODES_H\n'

        print '#define R_TRACE_CODES_LEN %d\n' % (len(data) * 2)

        print 'static const char * trace_codes[R_TRACE_CODES_LEN] = {'
        for entry in data:
            print '\t"%s", "%s",' % entry
        print '};\n'

        print '#endif'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'usage %s bsd/kern/trace_codes' % sys.argv[0]
    else:
        convert(sys.argv[1])

