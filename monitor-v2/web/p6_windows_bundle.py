"""Bounded streaming private client ZIP; signed software bytes stay unchanged."""
import hashlib
import io
import re
import struct
import zipfile
import zlib

from p6_distribution import DistributionError, MAX_FILES, MAX_MANIFEST, object_json, validate_manifest_record
from web.p6_bundle import MAX_BUNDLE_BYTES

MAX_CLIENT_PACKAGE = 70 * 1024 * 1024
CHUNK = 65536


def require_client_package(stream, manifest):
    """Called on a fully verified held publication before credential RPC.

    gui-v2 is the catalog-bound capability for Bundle v2 + adjacent discovery.
    Old signed gui-v1 remains valid for the legacy software-only download.
    """
    try:
        with zipfile.ZipFile(stream) as archive:
            row = archive.getinfo('payload/release.json')
            if row.file_size > MAX_MANIFEST:
                raise DistributionError()
            with archive.open(row) as source:
                raw = source.read(MAX_MANIFEST + 1)
            meta = object_json(raw)
            if len(raw) > MAX_MANIFEST or meta.get('entry') != 'gui-v2' \
                    or meta.get('release') != manifest['release']:
                raise DistributionError()
    except (zipfile.BadZipFile, KeyError, ValueError, TypeError, AttributeError):
        raise DistributionError() from None
    finally:
        stream.seek(0)


class WindowsClientPackage:
    """Caller holds the already validated publication file through transmission.

    Metadata is small; config bytes are bounded separately. Never extract a file,
    modify signatures, persist secrets or buffer the generic runtime archive.
    """
    def __init__(self, stream, manifest, bundle, yaml_name, yaml):
        self.manifest = validate_manifest_record(manifest)
        require_client_package(stream, self.manifest)
        if type(bundle) is not bytes or not 0 < len(bundle) <= MAX_BUNDLE_BYTES \
                or type(yaml_name) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,31}-mihomo.yaml', yaml_name) \
                or type(yaml) is not bytes or not 0 < len(yaml) <= 32768:
            raise DistributionError()
        self.archive = zipfile.ZipFile(stream)
        try:
            rows = self.archive.infolist()
            if len(rows) > MAX_FILES or len(rows) != len(manifest['files']) \
                    or len({r.filename for r in rows}) != len(rows) \
                    or {r.filename for r in rows} != set(manifest['files']):
                raise DistributionError()
            self.entries = []
            for row in sorted(rows,key=lambda r:r.filename):
                if row.compress_type != zipfile.ZIP_STORED or row.flag_bits & 1 \
                        or row.file_size != manifest['files'][row.filename]['size']:
                    raise DistributionError()
                self.entries.append((row.filename,row.file_size,row.CRC,row,None))
            scope = '受控测试版，不能用于正式发布。\n' if manifest['scope']=='lab' else ''
            readme = (scope+'Windows 客户端包\n\n'
                '1. 完整解压本包，保留同目录文件。\n'
                '2. 先将 '+yaml_name+' 导入并启用现有 Clash 客户端；按配置要求启用本机 API。\n'
                '3. 双击 P6Setup.exe 打开客户端管理；核对识别的设备后点击安装 / 更新。\n'
                '4. 关闭管理窗口后，后台服务继续采样和上传。\n\n'
                '本包包含此设备的密钥和代理配置，请私密保管，仅用于该设备。\n'
                '其他设备请分别登记并下载。不要将服务器证书安装到系统信任库。\n'
                '安装程序签名和文件完整性仍由 Windows 原生验证。\n').encode('utf-8')
            for name,raw in [('device-bundle.zip',bundle),(yaml_name,yaml),('README-client.txt',readme)]:
                self.entries.append((name,len(raw),zlib.crc32(raw)&0xffffffff,None,raw))
            if len(self.entries)>71:
                raise DistributionError()
            self.central = bytearray()
            offset = 0
            for name,size,crc,_,_ in self.entries:
                encoded = name.encode('ascii')
                self.central.extend(struct.pack('<4s6H3L5H2L',b'PK\x01\x02',788,20,0,0,0,33,
                    crc,size,size,len(encoded),0,0,0,0,0o100600<<16,offset)+encoded)
                offset += 30+len(encoded)+size
            if len(self.central)>65536:
                raise DistributionError()
            self.end = struct.pack('<4s4H2LH',b'PK\x05\x06',0,0,len(self.entries),len(self.entries),len(self.central),offset,0)
            self.size = offset+len(self.central)+len(self.end)
            if self.size>MAX_CLIENT_PACKAGE:
                raise DistributionError()
            self.used = False
        except BaseException:
            self.archive.close()
            raise

    def close(self):
        self.archive.close()

    def chunks(self):
        try:
            yield from self._chunks()
        except (zipfile.BadZipFile, struct.error, RuntimeError, ValueError):
            raise DistributionError() from None

    def _chunks(self):
        if self.used:
            raise DistributionError()
        self.used = True
        for name,size,crc,row,raw in self.entries:
            encoded = name.encode('ascii')
            yield struct.pack('<4s5H3L2H',b'PK\x03\x04',20,0,0,0,33,crc,size,size,len(encoded),0)+encoded
            digest = hashlib.sha256()
            with (self.archive.open(row) if row is not None else io.BytesIO(raw)) as source:
                remaining = size
                while remaining:
                    chunk = source.read(min(CHUNK,remaining))
                    if not chunk:
                        raise DistributionError()
                    remaining -= len(chunk)
                    digest.update(chunk)
                    yield chunk
                if source.read(1):
                    raise DistributionError()
            if row is not None and digest.hexdigest()!=self.manifest['files'][name]['sha256']:
                raise DistributionError()
        yield bytes(self.central)
        yield self.end
