import compileall
import sys


def main() -> int:
    ok = compileall.compile_dir('scanner', force=False, quiet=0)
    if ok:
        print('COMPILE_OK')
        return 0
    else:
        print('COMPILE_FAILED')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
