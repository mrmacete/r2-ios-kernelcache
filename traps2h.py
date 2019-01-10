import sys, json

def convert (json_file):
    with open(json_file, 'r') as f:
        data = json.loads(f.read())

        print '/* generated file, do not edit */\n'
        print '#ifndef R_MIG_ROUTINES_H'
        print '#define R_MIG_ROUTINES_H\n'

        print '#define R_MIG_ROUTINES_LEN %d\n' % (len(data) * 2)

        print 'static const char * mig_routines[R_MIG_ROUTINES_LEN] = {'
        for routine in data:
            print '\t"%s", "%s",' % (routine['num'], routine['name'])
        print '};\n'

        print '#endif'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'usage %s traps.json' % sys.argv[0]
    else:
        convert(sys.argv[1])

