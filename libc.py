from pwn import *
import Queue, threading
import re
import requests
import os
import fnmatch
from shutil import move, rmtree
from pyunpack import Archive

downq = Queue.Queue()
exq = Queue.Queue()
parseq = Queue.Queue()
libcq = Queue.Queue()


def findlibc(p):
    for root, dirs, files in os.walk(p):
        for filename in fnmatch.filter(files, 'libc.so.6'):
            return os.path.realpath(os.path.join(root, filename))


def md5_for_file(file, block_size=2 ** 20):
    f = open(file, 'rb')
    md5 = hashlib.md5()
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    f.close()
    return md5.hexdigest()


def libcparse():
    while not libcq.empty():
        libcp = libcq.get()
        libc = findlibc(libcp)
        log.success('found libc in ' + libc)
        context.log_level = 'ERROR'
        e = ELF(libc)
        context.log_level = 'INFO'
        md5 = md5_for_file(libc)
        with open(libcp + '.' + md5 + '.symbol', 'w') as f:
            f.write('bin_sh=' + hex(next(e.search('/bin/sh'))) + '\n')
            for sym, offset in e.symbols.iteritems():
                if sym != '':
                    f.write(sym + '=' + hex(offset) + '\n')
        move(libc, libcp + '.' + md5)
        rmtree(libcp)


def debparse():
    while not parseq.empty():
        deb, url = parseq.get()
        if os.path.isfile(deb):
            log.info('unpacking ' + deb)
            path = deb[:deb.index('.deb')]
            if not os.path.exists(path):
                os.makedirs(path)
            try:
                Archive(deb).extractall(path)
            except:
                log.error('error in unpacking ' + deb + ',restart downloading...')
                downq.put(url)
                threading.Thread(target=download_file).start()
                return
            libcq.put(path)
            os.remove(deb)
        threading.Thread(target=libcparse).start()


def download_file(url=None, tofile=None):
    while not downq.empty():
        if url is None:
            url = downq.get()
        if tofile is None:
            local_filename = url.split('/')[-1]
        else:
            local_filename = tofile
        log.success('Downloading {} to {}'.format(url, local_filename))
        # NOTE the stream=True parameter
        r = requests.get(url, stream=True)
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
        r.close()
        parseq.put((local_filename, url))
        threading.Thread(target=debparse).start()


def extractdeb():
    while not exq.empty():
        url, fetch_all = exq.get()
        log.success('Parsing url ' + url)
        exdeb = r"<a href=\"(.*(libc6(-amd64|-i386|)_\d.+?.deb))\""
        r = requests.get(url, timeout=5)
        r.close()
        matches = re.finditer(exdeb, r.content)
        for matchNum, match in enumerate(matches):
            if len(match.groups()) > 1:
                u = match.group(1)
                if not u.startswith('http'):
                    u = url + '/' + u
                log.success('Fecthed:' + u)
                downq.put(u)
                threading.Thread(target=download_file).start()
                if not fetch_all:
                    break


# fetch archs first
regex = r"<li><a href=\"(\w+)\/"
r = requests.get('http://packages.ubuntu.com/', timeout=5)
r.close()
matches = re.finditer(regex, r.content)
ver = []
pkglist = (('i386', 'libc6'), ('amd64', 'libc6'), ('amd64', 'libc6-i386'))
for matchNum, match in enumerate(matches):
    if len(match.groups()) == 1:
        ver.append(match.group(1))

for v in ver:
    for (x, y) in pkglist:
        url = 'http://packages.ubuntu.com/{}/{}/{}/download'.format(v, x, y)
        exq.put((url, False))
exq.put(('http://security.ubuntu.com/ubuntu/pool/main/e/eglibc/', True))
exq.put(('http://security.ubuntu.com/ubuntu/pool/main/g/glibc/', True))
# starting...
for x in xrange(10):
    threading.Thread(target=extractdeb).start()
