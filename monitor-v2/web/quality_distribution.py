"""Optional root-published quality app; private packages for prepared devices only."""
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit
import zipfile

ROOT = '/var/lib/singbox-quality-distribution'
PUBLISHER = '92E0176599764946F7E5AB332A5CEF150355BE9B'
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z')


class QualityUnavailable(ValueError):
    pass


def binding_id(name, device):
    if any(type(v) is not str or not NAME.fullmatch(v) for v in (name, device)):
        raise QualityUnavailable()
    return hashlib.sha256((name + '\0' + device).encode('ascii')).hexdigest()


def object_json(raw):
    def pairs(rows):
        result = {}
        for key,value in rows:
            if key in result: raise QualityUnavailable()
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def authority_directory(path):
    path = Path(path)
    for parent in (path, *path.parents):
        row = parent.lstat()
        if not stat.S_ISDIR(row.st_mode) or row.st_uid != 0 or row.st_mode & 0o022:
            raise QualityUnavailable()


@contextlib.contextmanager
def held(path, maximum, private=False):
    path = Path(path)
    authority_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        row, link = os.fstat(fd), path.lstat()
        import grp
        gid = grp.getgrnam('sboxweb').gr_gid if private else 0
        if (not stat.S_ISREG(row.st_mode) or row.st_uid != 0 or row.st_gid != gid
                or stat.S_IMODE(row.st_mode) != (0o640 if private else 0o644)
                or row.st_nlink != 1 or not 0 < row.st_size <= maximum
                or (row.st_dev,row.st_ino) != (link.st_dev,link.st_ino)):
            raise QualityUnavailable()
        with os.fdopen(fd,'rb',closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


def read(path, maximum, private=False):
    with held(path,maximum,private) as stream:
        raw = stream.read(maximum+1)
    if len(raw) > maximum: raise QualityUnavailable()
    return raw


def pair_checked(pair, name, device):
    if (type(pair) is not dict or set(pair) != {'v','name','device','info','certificate'}
            or type(pair['v']) is not int or pair['v'] != 1
            or pair['name'] != name or pair['device'] != device):
        raise QualityUnavailable()
    info = pair['info']
    if (type(info) is not dict or set(info) != {'v','endpoint','token','certificate_sha256'}
            or type(info['v']) is not int or info['v'] != 1
            or any(type(info[k]) is not str or not HEX.fullmatch(info[k]) for k in ('token','certificate_sha256'))
            or type(pair['certificate']) is not str or not 1 <= len(pair['certificate']) <= 16384):
        raise QualityUnavailable()
    ca = pair['certificate'].encode('ascii')
    if hashlib.sha256(ca).hexdigest() != info['certificate_sha256']: raise QualityUnavailable()
    endpoint = urlsplit(info['endpoint'])
    if (endpoint.scheme != 'https' or endpoint.username or endpoint.password or endpoint.query
            or endpoint.fragment or endpoint.path not in ('','/') or not 1024 <= endpoint.port <= 65535):
        raise QualityUnavailable()
    ip = ipaddress.ip_address(endpoint.hostname)
    if ip.is_unspecified or ip.is_multicast: raise QualityUnavailable()
    return ca


def record_checked(value, maximum):
    if (type(value) is not dict or set(value) != {'sha256','size'}
            or type(value['sha256']) is not str or not HEX.fullmatch(value['sha256'])
            or type(value['size']) is not int or not 0 < value['size'] <= maximum):
        raise QualityUnavailable()


@contextlib.contextmanager
def recipient(name, device, root=ROOT):
    """Hold and verify software before the caller dispatches a private YAML export."""
    try:
        ident = binding_id(name,device)
        current = object_json(read(Path(root)/'current.json',1024))
        if type(current) is not dict or set(current) != {'v','release'} or type(current['v']) is not int or current['v'] != 1 or not HEX.fullmatch(current['release']):
            raise QualityUnavailable()
        directory = Path(root)/'releases'/current['release']
        raw = read(directory/'release.json',16384)
        if hashlib.sha256(raw).hexdigest() != current['release']: raise QualityUnavailable()
        manifest = object_json(raw)
        if (type(manifest) is not dict or set(manifest) != {'v','publisher','software','notices','clients'}
                or type(manifest['v']) is not int or manifest['v'] != 1 or manifest['publisher'] != PUBLISHER
                or type(manifest['clients']) is not dict or not 1 <= len(manifest['clients']) <= 2
                or ident not in manifest['clients']):
            raise QualityUnavailable()
        record_checked(manifest['software'],16*1024*1024)
        record_checked(manifest['notices'],65536)
        for key,value in manifest['clients'].items():
            if not HEX.fullmatch(key): raise QualityUnavailable()
            record_checked(value,32768)
        pair_raw = read(directory/'clients'/(ident+'.json'),32768,True)
        expected = manifest['clients'][ident]
        if len(pair_raw) != expected['size'] or hashlib.sha256(pair_raw).hexdigest() != expected['sha256']:
            raise QualityUnavailable()
        pair = object_json(pair_raw)
        pair_checked(pair,name,device)
        notices = read(directory/'notices.txt',65536)
        if len(notices) != manifest['notices']['size'] or hashlib.sha256(notices).hexdigest() != manifest['notices']['sha256']:
            raise QualityUnavailable()
        with held(directory/'quality.exe',16*1024*1024) as software:
            digest = hashlib.sha256(); size = 0
            for block in iter(lambda:software.read(65536),b''):
                digest.update(block); size += len(block)
            if size != manifest['software']['size'] or digest.hexdigest() != manifest['software']['sha256']:
                raise QualityUnavailable()
            software.seek(0)
            software.quality_sha256 = manifest['software']['sha256']
            yield software,pair,notices
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        raise QualityUnavailable() from None


def package(software, pair, yaml, notices):
    name,device = pair['name'],pair['device']
    binding_id(name,device)
    ca = pair_checked(pair,name,device)
    if type(yaml) is not str or not 0 < len(yaml.encode('utf-8')) <= 32768:
        raise QualityUnavailable()
    files = {name+'-mihomo.yaml':yaml.encode('utf-8'), 'receiver-info.json':json.dumps(pair['info']).encode(),
             'receiver-ca.pem':ca}
    descriptor = {'v':1,'client':name,'files':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
    readme = ('质量切换（两台设备试用）\n\n完整解压，打开“质量切换.exe”，点“开启质量切换”。\n'
              '首次按提示导入生成的配置，全局模式选“质量自动选择”，再点开启。\n'
              '请保持 Clash 和本窗口运行；关闭窗口即停止质量控制。无需安装后台服务。\n'
              '本包仅供 '+name+' / '+device+' 使用，包含私密配置，不要分享或上传 GitHub。\n').encode('utf-8')
    output = tempfile.TemporaryFile()
    try:
        with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_STORED) as archive:
            with archive.open('质量切换.exe','w') as target:
                digest = hashlib.sha256(); copied = 0
                for block in iter(lambda:software.read(65536),b''):
                    copied += len(block)
                    if copied > 16*1024*1024: raise QualityUnavailable()
                    digest.update(block); target.write(block)
                if digest.hexdigest() != software.quality_sha256: raise QualityUnavailable()
            for key,value in dict(files,**{'quality-package.json':json.dumps(descriptor).encode(),
                                            '先看这里.txt':readme,'第三方许可.txt':notices}).items():
                archive.writestr(key,value)
        output.seek(0,os.SEEK_END); size = output.tell()
        if size > 17*1024*1024: raise QualityUnavailable()
        output.seek(0)
        return output,size
    except BaseException:
        output.close(); raise
