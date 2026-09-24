"""Inspect byte-field mappings without treating mapping presence as full decoding.

audit_schema takes asn1tools.parse_files/parse_string output, optionally normalized
by the caller for its transport profile. It never compiles or rewrites schemas.
"""
from collections import Counter
import argparse
import json

from .field_formats import builtin_field_format
from .decoder import SUPPORTED_FIELD_FORMATS
from collections.abc import Mapping


def audit_schema(modules, roots, *, field_formats=None, use_builtin_formats=True,
                 max_depth=64, max_entries=50000):
    """Return reachable OCTET STRING, BIT STRING and ANY paths for qualified roots.

    roots is an iterable of (module, type) pairs. Lists use representative index
    [0]; exact per-index overrides may differ at other indices. Recursive and
    unresolved definitions are reported, never counted as successfully covered.
    """
    if (type(max_depth) is not int or type(max_entries) is not int
            or not 1 <= max_depth <= 128 or max_entries < 1):
        raise ValueError('Invalid coverage traversal limits')
    if not isinstance(use_builtin_formats, bool):
        raise ValueError('use_builtin_formats must be a boolean')
    entries = []
    if field_formats is not None and not isinstance(field_formats, Mapping):
        raise ValueError('field_formats must be a mapping')
    overrides = field_formats or {}
    for path, fmt in overrides.items():
        if not isinstance(path, str) or not isinstance(fmt, str) or fmt not in SUPPORTED_FIELD_FORMATS:
            raise ValueError('Invalid field format mapping')

    def add(root, path, module, kind, status, fmt=None):
        if len(entries) >= max_entries:
            raise ValueError('Schema coverage entry limit exceeded')
        entries.append({'root': root, 'path': path, 'module': module, 'asn_type': kind,
                        'status': status, 'format': fmt})

    def walk(node, module, path, root, stack, depth):
        kind = node.get('type')
        if depth > max_depth:
            add(root, path, module, kind, 'depth-limit')
            return
        if kind in ('OCTET STRING', 'BIT STRING', 'ANY', 'ANY DEFINED BY'):
            fmt = overrides.get(path)
            if fmt is None and use_builtin_formats:
                fmt = builtin_field_format(path)
            # Field formats currently operate on octets, not ASN BIT STRING tuples.
            if kind not in ('OCTET STRING', 'ANY', 'ANY DEFINED BY'):
                add(root, path, module, kind, 'opaque')
                return
            fields = path.lower().split('.')
            sms = fields[-1] == 'content' and any(k in ('sms', 'sms-contents') for k in fields[:-1])
            if fmt is None and sms:
                fmt = 'sms-tpdu'
            add(root, path, module, kind, 'mapped' if fmt and fmt != 'hex' else 'opaque', fmt)
        elif kind in ('SEQUENCE', 'SET', 'CHOICE'):
            for member in node.get('members', []):
                # None denotes an ASN.1 extension marker; later named members
                # remain reachable. Unsupported parser nodes are reported.
                if member is None:
                    continue
                if not isinstance(member, dict) or 'name' not in member:
                    add(root, path, module, str(member), 'unresolved')
                    continue
                child = f"{path}.{member['name']}" if path else member['name']
                walk(member, module, child, root, stack, depth + 1)
        elif kind in ('SEQUENCE OF', 'SET OF'):
            walk(node['element'], module, path + '[0]', root, stack, depth + 1)
        elif kind in ('BOOLEAN', 'INTEGER', 'REAL', 'NULL', 'ENUMERATED', 'OBJECT IDENTIFIER',
                      'RELATIVE-OID', 'IA5String', 'UTF8String', 'PrintableString', 'NumericString',
                      'VisibleString', 'GeneralString', 'GraphicString', 'TeletexString', 'T61String',
                      'UniversalString', 'BMPString', 'UTCTime', 'GeneralizedTime', 'ObjectDescriptor'):
            return
        else:
            target = module
            if kind not in modules.get(module, {}).get('types', {}):
                matches = [name for name, imports in modules.get(module, {}).get('imports', {}).items()
                           if kind in imports]
                target = matches[0] if len(matches) == 1 else None
            key = (target, kind)
            if target is None or kind not in modules.get(target, {}).get('types', {}):
                add(root, path, module, kind, 'unresolved')
            elif key in stack:
                add(root, path, module, kind, 'recursive')
            else:
                walk(modules[target]['types'][kind], target, path, root, stack | {key}, depth + 1)

    for module, name in roots:
        if name not in modules.get(module, {}).get('types', {}):
            raise ValueError(f'Unknown root {module}:{name}')
        walk(modules[module]['types'][name], module, '', f'{module}:{name}', {(module, name)}, 0)
    return {'summary': dict(Counter(item['status'] for item in entries)), 'fields': entries,
            'note': 'Mapped means a dispatcher exists, not complete protocol support. List indices use [0].'}


def main():
    import asn1tools
    parser = argparse.ArgumentParser(description='Audit reachable ASN.1 byte fields and registered formats')
    parser.add_argument('schemas', nargs='+', help='ASN.1 files accepted by asn1tools')
    parser.add_argument('--root', action='append', required=True, help='Module:Type (repeatable)')
    parser.add_argument('--field-formats', help='JSON exact-path format overrides')
    parser.add_argument('--no-builtin-formats', action='store_true')
    args = parser.parse_args()
    overrides = None
    if args.field_formats:
        with open(args.field_formats, encoding='utf-8') as stream:
            overrides = json.load(stream)
    roots = []
    for root in args.root:
        if ':' not in root:
            parser.error('--root requires Module:Type')
        roots.append(tuple(root.split(':', 1)))
    result = audit_schema(asn1tools.parse_files(args.schemas), roots, field_formats=overrides,
                          use_builtin_formats=not args.no_builtin_formats)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
