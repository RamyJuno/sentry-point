# main.py

import sys
from core.controller import Controller

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <target1> [<target2> ...]")
        sys.exit(1)

    targets = sys.argv[1:]

    controller = Controller("config/settings.yaml")
    controller.run(targets)

if __name__ == "__main__":
    main()
