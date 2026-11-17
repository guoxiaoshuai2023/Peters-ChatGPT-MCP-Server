"""Render one native acceptance message from the single frozen loader template.

No service calls or native execution occur here. Independent release pins and
fixture expectations are explicit inputs. All data is serialized as JSON rather
than interpolated as executable Python. Output creation never overwrites a file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


MAX_TEMPLATE_BYTES = 64 * 1024
ASSET_KEYS = {'asset_id', 'name', 'bytes', 'sha256'}


def _sha(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise ValueError('invalid_sha256')
    return value


def _asset(value):
    if (not isinstance(value, dict) or set(value) != ASSET_KEYS
            or value['asset_id'] != 'native-chunk-receiver-v1'
            or value['name'] != 'native_chunk_receiver.py'
            or type(value['bytes']) is not int or not 1 <= value['bytes'] <= 65536):
        raise ValueError('invalid_expected_asset')
    _sha(value['sha256'])
    return dict(value)


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def _invalid_constant(_value):
    raise ValueError('invalid_json_constant')


def _read_json(path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique,
                      parse_constant=_invalid_constant)


def render_loading_code(loader_bytes, expected_loader_sha256, expected_asset,
                        parameters=None):
    """Render the exact template plus separately serialized optional data.

    With no known native paths yet, the code defines
    ``load_actual_received_helper`` for a later call with real host data. Passing
    a parameters object also renders that call and its measured output.
    """
    _sha(expected_loader_sha256)
    expected = _asset(expected_asset)
    if (not isinstance(loader_bytes, bytes) or not loader_bytes
            or len(loader_bytes) > MAX_TEMPLATE_BYTES
            or hashlib.sha256(loader_bytes).hexdigest() != expected_loader_sha256):
        raise ValueError('loader_template_mismatch')
    loader_bytes.decode('utf-8', errors='strict')
    if parameters is not None:
        keys = {'actual_helper_path', 'input_root', 'expected_input_identity',
                'plan_receiver_asset'}
        if not isinstance(parameters, dict) or set(parameters) != keys:
            raise ValueError('invalid_native_parameters')
    # repr of bytes/JSON strings is Python syntax for fixed literal data only.
    # No native path, project name, plan field or pin can insert Python code.
    code = (
        'import hashlib, json\n'
        'LOADER_SOURCE = ' + repr(loader_bytes) + '\n'
        'EXPECTED_LOADER_SHA256 = ' + repr(expected_loader_sha256) + '\n'
        'EXPECTED_ASSET = json.loads(' + repr(_json(expected)) + ')\n'
        'PARAMETERS = json.loads(' + repr(_json(parameters)) + ')\n'
        'if hashlib.sha256(LOADER_SOURCE).hexdigest() != EXPECTED_LOADER_SHA256:\n'
        '    raise RuntimeError("loader_template_mismatch")\n'
        'LOADER_NAMESPACE = {"__name__": "_frozen_native_receiver_loader"}\n'
        'exec(compile(LOADER_SOURCE, "frozen_native_receiver_loader.py", "exec", '
        'dont_inherit=True), LOADER_NAMESPACE)\n'
        'def load_actual_received_helper(actual_helper_path, input_root, '
        'expected_input_identity, plan_receiver_asset):\n'
        '    module, evidence = LOADER_NAMESPACE["load_verified_receiver"](actual_helper_path, '
        'input_root, expected_input_identity, EXPECTED_ASSET, plan_receiver_asset)\n'
        '    if evidence.get("native_receiver_root_bound") is not True:\n'
        '        raise RuntimeError("native_receiver_root_binding_required")\n'
        '    return module, evidence\n'
        'if PARAMETERS is not None:\n'
        '    RECEIVER_MODULE, LOADER_EVIDENCE = load_actual_received_helper(**PARAMETERS)\n'
        '    print(json.dumps(LOADER_EVIDENCE, sort_keys=True))\n'
    )
    return {'loader_bytes': len(loader_bytes),
            'loader_sha256': expected_loader_sha256,
            'expected_asset': expected, 'parameters': parameters,
            'loading_code': code,
            'loading_code_sha256': hashlib.sha256(code.encode('utf-8')).hexdigest()}


def _acceptance(value):
    keys = {'run_label', 'stage', 'project_id', 'worktree_id', 'source_path',
            'expected_bytes', 'expected_sha256', 'expected_png_sha256',
            'package_fingerprint', 'config_sha256'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('invalid_acceptance_data')
    if value['stage'] not in ('small', '30mb'):
        raise ValueError('invalid_acceptance_stage')
    expected_size = 8192 if value['stage'] == 'small' else 30_000_000
    if type(value['expected_bytes']) is not int or value['expected_bytes'] != expected_size:
        raise ValueError('invalid_acceptance_size')
    for name in ('run_label', 'project_id', 'worktree_id', 'source_path'):
        text = value[name]
        if (not isinstance(text, str) or not text or len(text.encode('utf-8')) > 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in text)):
            raise ValueError('invalid_acceptance_text')
    path = PurePosixPath(value['source_path'])
    if (not path.parts or path.is_absolute() or '\\' in value['source_path']
            or str(path) != value['source_path'] or '..' in path.parts):
        raise ValueError('invalid_source_path')
    for name in ('expected_sha256', 'expected_png_sha256',
                 'package_fingerprint', 'config_sha256'):
        _sha(value[name])
    return dict(value)


def render_prompt(loader_bytes, expected_loader_sha256, expected_asset,
                  acceptance_data, parameters=None):
    data = _acceptance(acceptance_data)
    rendered = render_loading_code(loader_bytes, expected_loader_sha256,
                                   expected_asset, parameters)
    stage_extra = ('本轮只签收8192字节小件，完成或失败都停止；不开始30 MB。'
                   if data['stage'] == 'small' else
                   '此前相同发行/config/helper/loader的小件已由本机主代理核对通过，'
                   '本轮只签收30,000,000字节，不测试50/70/200 MB。'
                   '若没有此前小门通过证据则停止，不自行推断。')
    prompt = (
        '执行 Peters MCP 原生文件验收，run=' + data['run_label'] + '。' + stage_extra + '\n\n'
        '只用既有 Peters ChatGPT MCP、GPT-5.6 Sol / Chat / High。分别记录实际模型/模式'
        '和用户UI档位证据，服务delivery profile不替代客户端事实。六个chunked工具必须实际'
        '可见。不得新建连接、扩大权限、改来源、发业务消息或原件写回。人工确认提示交给用户，'
        '不得代点允许或绕过。\n\n'
        '独立冻结发行、配置和原件约束如下；它们不是从新plan回抄的可信pin：\n```json\n'
        + json.dumps(data, ensure_ascii=False, indent=2) + '\n```\n'
        '固定helper和唯一loader约束：\n```json\n'
        + json.dumps({k: rendered[k] for k in ('loader_bytes', 'loader_sha256',
                                             'expected_asset', 'loading_code_sha256')},
                     ensure_ascii=False, indent=2) + '\n```\n\n'
        '1. 取得当前list_projects的service_instance_id/request_window_id，确认raw-parts-v1、'
        'enabled=true、configured_max_file_bytes=30000000、part_max_bytes=8000000。'
        '核实际工作树有效，main是默认目录ID而非分支名。用本run新request_key，按上述精确'
        'project/worktree/path/expected_sha256调用prepare_chunked_export；同ID有界查询，'
        '从get_chunked_export_plan实际envelope.plan核总字节/整体SHA/段几何和helper独立pin，'
        '保全完整计划及实参/响应。不要用ready代替收件。\n\n'
        '2. materialize_chunked_export_receiver后只用实际原生收件路径；先只读记录OS/Python/'
        'uid/euid/gid、实际INPUT_ROOT的dev/ino与路径链、helper全stat/字节SHA。'
        '缺失或不合格就停止，不猜路径、不复制或chmod/chown。执行下方唯一固定代码，'
        '再根据实际回执数据调用load_actual_received_helper(actual_helper_path, input_root, '
        'expected_input_identity, plan_receiver_asset)，其中input identity来自本次真实预检，'
        'plan asset来自实际plan。PARAMETERS为null时只是尚未绑定实际路径，不能据此称加载完成。'
        '必须实际得到LOADER_EVIDENCE.native_receiver_root_bound=true，确认后续接收器绑定'
        '本次预检输入根；缺少或false不得开始新原生任务，旧helper诊断不能代过。'
        '公开实际执行代码全文、实际调用数据和LOADER_EVIDENCE，不手写第二加载器、不importlib/'
        'runpy/pyc，不执行ZIP成员或业务代码。\n\n```python\n'
        + rendered['loading_code'] + '```\n\n'
        '3. loader通过后，仅用该RECEIVER_MODULE.NativeChunkReceiver。create-only建立本run'
        'currentUID的0700输出叶目录，实际INPUT_ROOT不改。start(plan,output_root,input_root,'
        'target_name)实际通过磁盘、session→output_root跨目录无覆盖hardlink与双方fsync预检，'
        '任何start/预检异常先公开原异常类型、错误码/文本、本次已建output_root以及'
        'getattr(error,"preflight",None)原始可序列化清单，保全每个probe的实际路径/identity/'
        'retained/removed/unknown；不能只打印异常码或把unknown猜成已删。随后仅按第6项'
        '源端收尾例外处理，不调用receiver.cleanup。失败不降级复制发布，不修改平台根。'
        '只在预检通过后按计划索引串行materialize part。'
        '每段的真实路径、完整stat、独立长度SHA先公开再ingest，不猜文件名，不混plan。\n\n'
        '4. small只取一段；30mb须四段8M/8M/8M/6M，段0重复ingest验证appended_bytes=0，'
        '然后新Python对象resume同session再继续。保留实际pending/ledger和所有异常；报错不'
        '代表零写入或零提交，禁止回滚/删除进度、自动finish或新plan补段掩盖失败。\n\n'
        '5. finish后独立重新打开最终ZIP核精确总字节和上述独立源SHA，ZipFile.testzip、成员'
        '清单与安全解包；visual.png完整解码8×8 RGBA、核上述PNG SHA并实际展示。保留helper、'
        '原生输入段、计划、账本、最终件和公开关键原始结果。\n\n'
        '6. 成功或身份/hash/权限/加载/持久性/发布失败均立即停止所有数据面操作，先保全错误'
        '和现场。唯一收尾例外明确授权：仅对本run已知export_id调用cancel_chunked_export，'
        '有界status/cancel合计最多12次、总观察60秒；保留实际原始响应。不能从cancelled/'
        'TTL推断释放，只有实际resources_released=true才记录服务自报释放；本机主代理另核'
        '同ID审计/owner/SDK/ASGI/FD/预算。未证实就写pending/unknown，不再prepare或取件。'
        '人工按钮仍交用户，不调用receiver.cancel/cleanup，不删除任何输入/成品，不取消旧或'
        '未知任务。最终公开完整实参/响应、plan、loader代码和证据、实际文件测量、receiver'
        '终态或失败现场、独立CRC/图像及源收尾；不得只把关键证据写进可能丢失的临时JSON。\n'
    )
    return {**rendered, 'acceptance_data': data, 'prompt': prompt,
            'prompt_sha256': hashlib.sha256(prompt.encode('utf-8')).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--loader', type=Path,
                        default=Path(__file__).with_name('native_receiver_loader.py'))
    parser.add_argument('--expected-loader-sha256', required=True)
    parser.add_argument('--expected-asset-manifest', type=Path, required=True,
                        help='Independent frozen release JSON: asset_id,name,bytes,sha256')
    parser.add_argument('--parameters', type=Path,
                        help='Optional JSON: actual_helper_path,input_root,expected_input_identity,plan_receiver_asset')
    parser.add_argument('--acceptance-data', type=Path,
                        help='JSON: run_label,stage,project_id,worktree_id,source_path,expected_bytes,expected_sha256,expected_png_sha256,package_fingerprint,config_sha256')
    parser.add_argument('--format', choices=('json', 'markdown', 'code'), default='markdown')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        loader = args.loader.read_bytes()
        asset = _read_json(args.expected_asset_manifest)
        parameters = _read_json(args.parameters) if args.parameters else None
        if args.acceptance_data:
            rendered = render_prompt(loader, args.expected_loader_sha256, asset,
                                     _read_json(args.acceptance_data), parameters)
        else:
            rendered = render_loading_code(loader, args.expected_loader_sha256, asset, parameters)
        if args.format == 'json':
            raw = json.dumps(rendered, ensure_ascii=False, indent=2) + '\n'
        elif args.format == 'code':
            raw = rendered['loading_code']
        else:
            raw = rendered.get('prompt', '```python\n' + rendered['loading_code'] + '```\n')
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            # fdopen owns the descriptor; never retry an uncertain close.
            raise
        print(json.dumps({'output': str(args.output),
                          'bytes': len(raw.encode('utf-8')),
                          'sha256': hashlib.sha256(raw.encode('utf-8')).hexdigest(),
                          'loader_sha256': rendered['loader_sha256']}))
    except (OSError, ValueError, TypeError, UnicodeError, KeyError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
