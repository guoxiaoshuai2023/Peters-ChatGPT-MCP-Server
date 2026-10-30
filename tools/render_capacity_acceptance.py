"""Render bounded capacity acceptance using the frozen loader and public A/B IO.

This is an operator-side tool. It never calls MCP, starts a service, or executes
received business files. Native A and B are deliberately separate API calls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from types import ModuleType

REPO = Path(__file__).resolve().parents[1]
FROZEN_ROOT = REPO / 'versions/0.4.4-progressive.2'
PART_BYTES = 8_000_000
MAX_BYTES = 100_000_000
LOADER_SHA256 = '5a539432ae8796ee880ae8a3c128e18718991233a239e8133eec7b55091150cc'
RENDERER_SHA256 = '22199d34c57c123d54f399e9dd7bc5a00f0b6d31d4a67f96e686ef36e542035d'
EXPECTED_ASSET = {'asset_id': 'native-chunk-receiver-v1', 'name': 'native_chunk_receiver.py',
                  'bytes': 57452, 'sha256': 'fbe30b9e3ed604e246f9fa559524780ea7c03eec254fcae6e34faecc1d1662f7'}

# This trusted control source is published once. It is not another receiver
# loader; the supplied module must already be bound by the frozen loader.
COMMON_CONTROL_SOURCE = r'''import hashlib, json, os, stat, time
from pathlib import Path
from datetime import datetime, timezone

class CapacityRun:
    @staticmethod
    def _stamp(s):
        return {k: int(getattr(s, 'st_' + k)) for k in
                ('dev','ino','size','mtime_ns','ctime_ns','nlink','uid','gid','mode')}

    @staticmethod
    def _id(s):
        return [int(s.st_dev), int(s.st_ino)]

    @staticmethod
    def _directory(path):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise RuntimeError('unsafe_directory')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name in path.parts[1:]:
                new = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                old, fd = fd, new
                os.close(old)
            result, fd = fd, None
            return result
        finally:
            if fd is not None:
                os.close(fd)

    @classmethod
    def configure(cls, plan, receiver_module, input_root, expected_input_identity,
                  output_root, run_label, expected_parts, accepted_at_unix,
                  target_name='received-original.zip'):
        self = cls()
        self.plan = receiver_module.normalize_plan(plan)
        self.module = receiver_module
        self.input_root, self.output_root = str(Path(input_root)), str(Path(output_root))
        self.input_identity = list(expected_input_identity)
        if (len(self.input_identity) != 2 or any(type(x) is not int for x in self.input_identity)
                or receiver_module.NativeChunkReceiver._native_input_binding() !=
                   (self.input_root, tuple(self.input_identity))):
            raise RuntimeError('verified_native_root_binding_required')
        if type(accepted_at_unix) not in (int, float) or not 0 < accepted_at_unix <= time.time():
            raise RuntimeError('invalid_acceptance_clock')
        self.accepted_at_unix = accepted_at_unix
        if (not isinstance(expected_parts, list) or len(expected_parts) != self.plan['part_count']
                or any({k: x[k] for k in ('index','offset','bytes','sha256')} !=
                       {k: y[k] for k in ('index','offset','bytes','sha256')}
                       for x, y in zip(expected_parts, self.plan['parts']))):
            raise RuntimeError('independent_source_parts_mismatch')
        self.expected_parts = json.loads(json.dumps(expected_parts))
        self.run_label, self.measurements = run_label, {}
        root = self._directory(self.input_root)
        try:
            if self._id(os.fstat(root)) != self.input_identity:
                raise RuntimeError('input_root_identity_changed')
        finally:
            os.close(root)
        self.receiver = receiver_module.NativeChunkReceiver.start(
            self.plan, self.output_root, input_root=self.input_root, target_name=target_name)
        output = self._directory(self.output_root)
        try:
            os.mkdir('receipts', mode=0o700, dir_fd=output)
            os.fsync(output)
        finally:
            os.close(output)
        self.receipts_root = str(Path(self.output_root) / 'receipts')
        fd = self._directory(self.receipts_root)
        try:
            self.receipts_identity = self._id(os.fstat(fd))
            self._private_directory(fd)
        finally:
            os.close(fd)
        return self

    def _private_directory(self, fd):
        st = os.fstat(fd)
        if (st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) not in (0o700,0o2700)
                or self._id(st) != self.receipts_identity):
            raise RuntimeError('receipt_directory_changed')

    def _read_receipt(self, name, expected_sha):
        parent = self._directory(self.receipts_root)
        try:
            self._private_directory(parent)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before, named = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                        or before.st_size > 65536 or self._stamp(before) != self._stamp(named)):
                    raise RuntimeError('unsafe_receipt')
                blocks, total = [], 0
                while True:
                    b = os.read(fd, 8192)
                    if not b:
                        break
                    total += len(b)
                    if total > 65536:
                        raise RuntimeError('receipt_too_large')
                    blocks.append(b)
                raw = b''.join(blocks)
                after, named_after = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (self._stamp(before) != self._stamp(after) or
                        self._stamp(after) != self._stamp(named_after) or
                        len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected_sha):
                    raise RuntimeError('receipt_changed_or_hash_mismatch')
            finally:
                os.close(fd)
            self._private_directory(parent)
        finally:
            os.close(parent)
        return raw, {'stat': self._stamp(after), 'bytes': len(raw),
                     'sha256': expected_sha, 'file_close': True, 'directory_close': True}

    def _publish(self, name, value):
        raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',',':'))+'\n').encode()
        digest = hashlib.sha256(raw).hexdigest()
        parent = self._directory(self.receipts_root)
        writes = []
        try:
            self._private_directory(parent)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            try:
                pos = 0
                while pos < len(raw):
                    n = os.write(fd, raw[pos:]); writes.append(n)
                    if n <= 0:
                        raise RuntimeError('receipt_short_write')
                    pos += n
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
            self._private_directory(parent)
        finally:
            os.close(parent)
        actual, evidence = self._read_receipt(name, digest)
        if actual != raw:
            raise RuntimeError('receipt_readback_mismatch')
        return {'path': str(Path(self.receipts_root)/name), 'buffer_bytes':len(raw),
                'buffer_sha256':digest, 'write_returns':writes, 'file_fsync':True,
                'write_close':True, 'directory_fsync':True, 'directory_close':True,
                'readback_exact':True, 'readback':evidence}

    def _measure_input(self, actual_path):
        actual = Path(actual_path)
        relative = actual.relative_to(Path(self.input_root))
        if (not actual.is_absolute() or not relative.parts or
                any(x in ('','.','..') for x in relative.parts)):
            raise RuntimeError('part_outside_bound_root')
        root = self._directory(self.input_root)
        held = [root]
        routes = []
        try:
            root_st = os.fstat(root)
            if self._id(root_st) != self.input_identity:
                raise RuntimeError('input_root_identity_changed')
            for name in relative.parts[:-1]:
                parent = held[-1]
                child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent)
                held.append(child); routes.append((parent,name,child))
            parent, name = held[-1], relative.parts[-1]
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd); named_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                forbidden = stat.S_IWGRP|stat.S_IWOTH|stat.S_ISUID|stat.S_ISGID|stat.S_ISVTX
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_uid not in (os.getuid(),0) or before.st_mode & forbidden
                        or self._stamp(before) != self._stamp(named_before)
                        or before.st_size > 8000000):
                    raise RuntimeError('unsafe_received_part')
                h, total = hashlib.sha256(), 0
                while True:
                    b = os.read(fd, 65536)
                    if not b:
                        break
                    h.update(b); total += len(b)
                    if total > 8000000:
                        raise RuntimeError('received_part_too_large')
                after = os.fstat(fd); named_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if self._stamp(before) != self._stamp(after) or self._stamp(after) != self._stamp(named_after):
                    raise RuntimeError('received_part_changed')
            finally:
                os.close(fd)
            for p, n, child in routes:
                if self._id(os.stat(n, dir_fd=p, follow_symlinks=False)) != self._id(os.fstat(child)):
                    raise RuntimeError('part_parent_route_changed')
            check = self._directory(self.input_root)
            try:
                if self._id(os.fstat(check)) != self.input_identity:
                    raise RuntimeError('input_root_route_changed')
            finally:
                os.close(check)
        finally:
            # Each close is attempted once; propagate uncertain close failures.
            failures = []
            for item in reversed(held):
                try:
                    os.close(item)
                except OSError as error:
                    failures.append(error)
            if failures:
                raise failures[0]
        return {'actual_part_path':str(actual), 'root_identity':self.input_identity,
                'root_fd_stat':self._stamp(root_st), 'part_named_before':self._stamp(named_before),
                'part_fd_before':self._stamp(before), 'part_fd_after':self._stamp(after),
                'part_named_after':self._stamp(named_after), 'actual_bytes':total,
                'actual_sha256':h.hexdigest(), 'root_close':True, 'part_close':True,
                'all_parent_descriptors_closed':True, 'file_policy_pass':True, 'stamps_equal':True}

    def A(self, index, actual_path):
        if time.time()-self.accepted_at_unix >= 2700:
            raise RuntimeError('operation_budget_exhausted_stop_new_reads')
        if type(index) is not int or not 0 <= index < self.plan['part_count']:
            raise RuntimeError('invalid_part_index')
        if self.receiver.status()['next_index'] != index:
            raise RuntimeError('out_of_order_measurement')
        measurement = self._measure_input(actual_path)
        pin = self.expected_parts[index]
        if (measurement['actual_bytes'] != pin['bytes'] or
                measurement['actual_sha256'] != pin['sha256']):
            raise RuntimeError('independent_part_pin_mismatch')
        measurement.update(run=self.run_label, phase='4A', index=index,
            observed_at_utc=datetime.now(timezone.utc).isoformat(), independent_pin=pin,
            plan_part=self.plan['parts'][index], ingest_called=False)
        receipt = self._publish('part-%04d-measurement.json'%index, measurement)
        self.measurements[index] = json.loads(json.dumps(measurement))
        return {'phase':'4A', 'index':index, 'measurement':measurement,
                'receipt':receipt, 'ingest_called':False}

    def B(self, index, measurement_receipt_sha256):
        if index not in self.measurements:
            raise RuntimeError('published_measurement_state_missing')
        raw, evidence = self._read_receipt('part-%04d-measurement.json'%index,
                                         measurement_receipt_sha256)
        measurement = json.loads(raw)
        if measurement != self.measurements[index]:
            raise RuntimeError('published_measurement_changed')
        # Recheck root and route without rereading data; ingest independently
        # hashes the complete input again under its bound-root file lease.
        root = self._directory(self.input_root)
        try:
            if self._id(os.fstat(root)) != measurement['root_identity']:
                raise RuntimeError('root_changed_since_measurement')
        finally:
            os.close(root)
        if self._stamp(os.stat(measurement['actual_part_path'],follow_symlinks=False)) != measurement['part_named_after']:
            raise RuntimeError('part_changed_since_measurement')
        result = self.receiver.ingest(index, measurement['actual_part_path'])
        status = self.receiver.status()
        received = sum(p['bytes'] for p in self.plan['parts'][:index+1])
        if (result.get('appended_bytes') != self.plan['parts'][index]['bytes']
                or status.get('next_index') != index+1 or status.get('received_bytes') != received
                or status.get('pending_part_index') is not None):
            raise RuntimeError('accepted_progress_mismatch_preserve_state')
        duplicate = resume = None
        if index == 0:
            duplicate = self.receiver.ingest(0, measurement['actual_part_path'])
            if duplicate.get('appended_bytes') != 0:
                raise RuntimeError('duplicate_append_mismatch')
            previous = self.receiver
            self.receiver = self.module.NativeChunkReceiver.resume(
                previous.session_path, self.plan, input_root=self.input_root)
            resume = {'new_object':self.receiver is not previous, 'status':self.receiver.status()}
            if not resume['new_object'] or resume['status']['received_bytes'] != received:
                raise RuntimeError('resume_progress_mismatch')
        acceptance = {'run':self.run_label, 'phase':'4B', 'index':index,
            'observed_at_utc':datetime.now(timezone.utc).isoformat(),
            'measurement_receipt':evidence, 'measurement_receipt_sha256':measurement_receipt_sha256,
            'root_identity_rechecked':measurement['root_identity'],
            'part_stat_rechecked':measurement['part_named_after'],
            'ingest_result':result, 'status_after_ingest':status,
            'duplicate_result':duplicate, 'new_object_resume':resume}
        receipt = self._publish('part-%04d-acceptance.json'%index, acceptance)
        return {'phase':'4B', 'index':index, 'acceptance':acceptance, 'receipt':receipt}
'''
COMMON_CONTROL_SHA256 = hashlib.sha256(COMMON_CONTROL_SOURCE.encode()).hexdigest()


def _sha(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise ValueError('invalid_sha256')
    return value


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _frozen_renderer():
    path = FROZEN_ROOT / 'tools/render_native_acceptance_prompt.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != RENDERER_SHA256:
        raise ValueError('frozen_renderer_changed')
    module = ModuleType('_frozen_capacity_loading_renderer')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def validate_acceptance(value):
    required = {'run_label', 'project_id', 'worktree_id', 'source_path', 'expected_bytes',
                'expected_sha256', 'expected_png_sha256', 'package_fingerprint', 'config_sha256',
                'legacy_source_path', 'legacy_expected_bytes', 'legacy_expected_sha256', 'part_hashes'}
    optional = {'configured_max_file_bytes', 'part_count', 'parts'}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys()-required-optional:
        raise ValueError('invalid_acceptance_data')
    data = dict(value)
    capacity = data.setdefault('configured_max_file_bytes', 30_000_000)
    size = data['expected_bytes']
    if (type(capacity) is not int or not 8192 <= capacity <= MAX_BYTES or
            type(size) is not int or size != capacity or data['legacy_expected_bytes'] != 8192
            or type(data['legacy_expected_bytes']) is not int):
        raise ValueError('invalid_acceptance_capacity')
    for key in ('run_label', 'project_id', 'worktree_id', 'source_path', 'legacy_source_path'):
        text = data[key]
        if (not isinstance(text, str) or not text or len(text.encode()) > 4096 or
                any(ord(c) < 32 or ord(c) == 127 for c in text) or '```' in text):
            raise ValueError('invalid_acceptance_text')
    for key in ('source_path', 'legacy_source_path'):
        path = PurePosixPath(data[key])
        if (path.is_absolute() or '\\' in data[key] or str(path) != data[key]
                or any(p in ('', '.', '..') for p in path.parts)):
            raise ValueError('invalid_source_path')
    for key in ('expected_sha256','expected_png_sha256','package_fingerprint','config_sha256',
                'legacy_expected_sha256'):
        _sha(data[key])
    parts = [{'index':i, 'offset':i*PART_BYTES, 'bytes':min(PART_BYTES,size-i*PART_BYTES)}
             for i in range((size+PART_BYTES-1)//PART_BYTES)]
    if 'part_count' in data and (type(data['part_count']) is not int or data['part_count'] != len(parts)):
        raise ValueError('inconsistent_part_geometry')
    if 'parts' in data and _json(data['parts']) != _json(parts):
        raise ValueError('inconsistent_part_geometry')
    if 'part_hashes' in data:
        if not isinstance(data['part_hashes'], list) or len(data['part_hashes']) != len(parts):
            raise ValueError('invalid_independent_part_hashes')
        for part, digest in zip(parts, data['part_hashes']):
            part['sha256'] = _sha(digest)
    data.update(part_count=len(parts), parts=parts)
    return data


def render_prompt(loader_bytes, expected_loader_sha256, expected_asset, acceptance_data, parameters=None):
    data = validate_acceptance(acceptance_data)
    if expected_loader_sha256 != LOADER_SHA256 or expected_asset != EXPECTED_ASSET:
        raise ValueError('independent_release_pin_mismatch')
    rendered = _frozen_renderer().render_loading_code(
        loader_bytes, expected_loader_sha256, expected_asset, parameters)
    code = rendered['loading_code'] + '\n' + COMMON_CONTROL_SOURCE
    prompt = (
        '执行 Peters MCP 本轮原生容量验收。只使用当前既有连接、主账户和 Chrome 原会话；'
        '记录实际模型/模式/UI档位。人工认证或允许一次交给用户；不新建连接、扩大来源或写回仓库。\n'
        '独立固定发行和源约束如下，不能从本次服务 plan 回抄：\n```json\n' +
        json.dumps(data, ensure_ascii=False, indent=2) + '\n```\n'
        '先保全真实 list_projects，确认 raw-parts-v1、configured_max_file_bytes=' + str(data['configured_max_file_bytes']) +
        '、part_max_bytes=8000000、helper独立pin和旧出口12659780。先以全新请求键调用旧export_file获取上述'
        '8192字节legacy源；只用实际原生收件路径独立长度/SHA核验，失败即停止。\n'
        '随后全新请求键 prepare_chunked_export上述大件，只查询同一export；保全实际envelope.plan并核总字节、'
        'SHA、13段或所列几何及helper独立pin。记录prepare真实接受时间，45分钟内停止新取件；父3600秒、'
        'delivery600秒不延长。每次materialize前核真实时钟，不能猜路径、混plan或重建丢失状态。\n'
        '取真实 materialize_chunked_export_receiver 附件，记录INPUT_ROOT真实大整数dev/ino、uid、完整stat。'
        '执行下列完整固定代码；LOADER_SOURCE仍为冻结原字节，先关闭输入再执行同缓冲。'
        '调用load_actual_received_helper实际参数，必须得到native_receiver_root_bound=true。'
        'create-only新currentUID私有0700输出叶，然后CapacityRun.configure(actual_plan, RECEIVER_MODULE, '
        'input_root, expected_input_identity, output_root, run_label, 独立源parts含sha256, accepted_at_unix)。'
        'start空间/硬链接/fsync预检失败保全异常及preflight清单，不降级复制发布。\n'
        '公共代码只完整公开一次及SHA；每段串行materialize真实原生附件，随后单独Python调用'
        'print(json.dumps(run.A(index,actual_path),ensure_ascii=False,indent=2))，完整公开A原始输出并结束调用。'
        '后续另一次Python调用print(json.dumps(run.B(index,公开A的receipt.buffer_sha256),ensure_ascii=False,indent=2))。'
        '不得在同一Python调用执行A和B；A不调用ingest，B重读实际已持久化A再接收；段0内验证dup0和新对象resume。'
        '每段只保留这两份原始输出和索引，不逐段复印函数或截图。\n'
        '全部段完成后run.receiver.finish()，独立重新打开最终件核精确总字节/源整体SHA、ZIP CRC、成员清单、'
        '安全解包；visual.png完整解码8x8 RGBA、核源PNG SHA并实际展示。只执行可信接收器/控制代码，'
        '不执行ZIP成员或业务代码。保全helper、输入段、plan、session和最终件。\n'
        '成功或失败均先保全错误和现场，再仅对本轮已知legacy/chunked export收尾：对应cancel/status'
        '合计最多12次、总观察60秒；只对有cancel API的本轮已知ID使用对应通道，不能混ID或取消未知任务。'
        '真实resources_released/snapshot关闭证据不足则标pending/unknown，不从cancelled/TTL/server_stream_finished推断；'
        '主Agent另核审计/owner/SDK/ASGI/FD/预算。不要receiver.cancel/cleanup、删除文件或自动重跑。\n'
        '固定loader代码和A/B控制代码（完整公开，后续只调用）：\n```python\n' + code + '\n```\n'
        '代码SHA：' + hashlib.sha256(code.encode()).hexdigest() + '；公共A/B SHA：' + COMMON_CONTROL_SHA256 + '\n')
    return {**rendered, 'acceptance_data':data, 'common_control_code':COMMON_CONTROL_SOURCE,
            'common_control_sha256':COMMON_CONTROL_SHA256, 'control_code':code,
            'control_code_sha256':hashlib.sha256(code.encode()).hexdigest(), 'prompt':prompt,
            'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest()}


def read_json(path):
    def unique(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError('duplicate_json_key')
            d[k] = v
        return d
    def bad_constant(value):
        raise ValueError('invalid_json_constant')
    return json.loads(Path(path).read_text(), object_pairs_hook=unique, parse_constant=bad_constant)


def write_new(path, raw):
    path = Path(path)
    if path.parent.resolve() != path.parent.absolute():
        raise ValueError('linked_output_parent')
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    try:
        pos = 0
        while pos < len(raw):
            count = os.write(fd, raw[pos:])
            if count <= 0:
                raise OSError('short_output_write')
            pos += count
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--loader', type=Path, default=FROZEN_ROOT/'tools/native_receiver_loader.py')
    p.add_argument('--expected-loader-sha256', required=True)
    p.add_argument('--expected-asset-manifest', type=Path, required=True)
    p.add_argument('--acceptance-data', type=Path, required=True)
    p.add_argument('--parameters', type=Path)
    p.add_argument('--format', choices=('json','markdown','code'), default='markdown')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        result = render_prompt(args.loader.read_bytes(), args.expected_loader_sha256,
                               read_json(args.expected_asset_manifest), read_json(args.acceptance_data),
                               read_json(args.parameters) if args.parameters else None)
        output = (json.dumps(result, ensure_ascii=False, indent=2)+'\n' if args.format=='json' else
                  result['control_code'] if args.format=='code' else result['prompt'])
        write_new(args.output, output.encode())
        print(json.dumps({'output':str(args.output),'bytes':len(output.encode()),
                          'sha256':hashlib.sha256(output.encode()).hexdigest(),
                          'control_code_sha256':result['control_code_sha256']}))
    except (OSError, ValueError, TypeError, UnicodeError, KeyError) as e:
        p.exit(1, str(e)+'\n')

if __name__ == '__main__':
    main()
