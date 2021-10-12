import sys
from ryu.cmd import manager

def main():
    sys.argv.append('/home/parallels/Desktop/SwitchingAccessLine/controller.py')
    sys.argv.append('--enable-debugger')
    manager.main()

if __name__ == '__main__':
    main()
