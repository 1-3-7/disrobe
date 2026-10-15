import json
import os
import plistlib
import sys

out_dir = sys.argv[1]


class Archive:
    def __init__(self):
        self.objects: list = ['$null']
        self.classes = {}

    def add(self, value):
        self.objects.append(value)
        return plistlib.UID(len(self.objects) - 1)

    def reserve(self):
        self.objects.append(None)
        return len(self.objects) - 1

    def klass(self, name, chain):
        if name not in self.classes:
            self.classes[name] = self.add({'$classname': name, '$classes': [name] + chain})
        return self.classes[name]

    def string(self, text):
        return self.add(text)

    def ns_string(self, text, mutable=False, as_bytes=False):
        name = 'NSMutableString' if mutable else 'NSString'
        chain = ['NSString', 'NSObject'] if mutable else ['NSObject']
        body = {'NS.bytes': text.encode('utf-8')} if as_bytes else {'NS.string': text}
        return self.add({'$class': self.klass(name, chain), **body})

    def array(self, items, mutable=False):
        name = 'NSMutableArray' if mutable else 'NSArray'
        chain = ['NSArray', 'NSObject'] if mutable else ['NSObject']
        return self.add({'$class': self.klass(name, chain), 'NS.objects': items})

    def set(self, items):
        return self.add({'$class': self.klass('NSSet', ['NSObject']), 'NS.objects': items})

    def dictionary(self, pairs, mutable=False):
        name = 'NSMutableDictionary' if mutable else 'NSDictionary'
        chain = ['NSDictionary', 'NSObject'] if mutable else ['NSObject']
        return self.add({'$class': self.klass(name, chain), 'NS.keys': [k for k, _ in pairs],
                         'NS.objects': [v for _, v in pairs]})

    def data(self, raw):
        return self.add({'$class': self.klass('NSData', ['NSObject']), 'NS.data': raw})

    def date(self, seconds):
        return self.add({'$class': self.klass('NSDate', ['NSObject']), 'NS.time': seconds})

    def url(self, relative, base=None):
        return self.add({'$class': self.klass('NSURL', ['NSObject']), 'NS.base': base or plistlib.UID(0),
                         'NS.relative': self.string(relative)})

    def uuid(self, raw):
        return self.add({'$class': self.klass('NSUUID', ['NSObject']), 'NS.uuidbytes': raw})

    def null(self):
        return self.add({'$class': self.klass('NSNull', ['NSObject'])})

    def write(self, name, top, xml=False):
        root = {'$archiver': 'NSKeyedArchiver', '$version': 100000, '$top': top, '$objects': self.objects}
        if xml:
            payload = plistlib.dumps(to_xml(root), fmt=plistlib.FMT_XML)
        else:
            payload = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        with open(os.path.join(out_dir, name), 'wb') as handle:
            handle.write(payload)


def to_xml(value):
    if isinstance(value, plistlib.UID):
        return {'CF$UID': value.data}
    if isinstance(value, dict):
        return {key: to_xml(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_xml(item) for item in value]
    return value


truth = {}

basic = Archive()
uid_bytes = bytes(range(0x10, 0x20))
pairs = [
    (basic.string('name'), basic.ns_string('disrobe')),
    (basic.string('count'), basic.add(42)),
    (basic.string('ratio'), basic.add(0.5)),
    (basic.string('enabled'), basic.add(True)),
    (basic.string('tags'), basic.array([basic.string('alpha'), basic.string('beta')], mutable=True)),
    (basic.string('blob'), basic.data(b'\x00\x01\xfe\xff')),
    (basic.string('when'), basic.date(700000000.5)),
    (basic.string('home'), basic.url('https://example.org/path')),
    (basic.string('id'), basic.uuid(uid_bytes)),
    (basic.string('nothing'), plistlib.UID(0)),
    (basic.string('null'), basic.null()),
    (basic.string('numbers'), basic.set([basic.add(1), basic.add(2)])),
    (basic.string('note'), basic.ns_string('bytes form', as_bytes=True)),
    (basic.string('large'), basic.add(2 ** 40)),
    (basic.string('negative'), basic.add(-7)),
]
root = basic.dictionary(pairs, mutable=True)
basic.write('basic.bplist', {'root': root})
basic.write('basic.xml', {'root': root}, xml=True)
expected_basic = {'dict': 'NSMutableDictionary', 'entries': [
    ['name', 'disrobe'], ['count', 42], ['ratio', 0.5], ['enabled', True],
    ['tags', {'array': 'NSMutableArray', 'items': ['alpha', 'beta']}],
    ['blob', {'data': '0001feff'}], ['when', {'date': 700000000.5}],
    ['home', {'url': {'base': None, 'relative': 'https://example.org/path'}}],
    ['id', {'uuid': '10111213-1415-1617-1819-1A1B1C1D1E1F'}],
    ['nothing', None], ['null', None],
    ['numbers', {'set': 'NSSet', 'items': [1, 2]}],
    ['note', 'bytes form'], ['large', 2 ** 40], ['negative', -7],
]}
truth['basic.bplist'] = {'top': {'root': expected_basic}}
truth['basic.xml'] = {'top': {'root': expected_basic}}

graph = Archive()
alice_index = graph.reserve()
bob_index = graph.reserve()
person = graph.klass('Person', ['NSObject'])
alice_uid = plistlib.UID(alice_index)
bob_uid = plistlib.UID(bob_index)
graph.objects[alice_index] = {'$class': person, 'name': graph.string('Alice'), 'age': 31, 'friend': bob_uid,
                              'self': alice_uid}
graph.objects[bob_index] = {'$class': person, 'name': graph.string('Bob'), 'age': 29, 'friend': alice_uid}
crowd = graph.array([bob_uid, bob_uid])
graph.write('graph.bplist', {'root': alice_uid, 'crowd': crowd})
bob_from_alice = {'object': 'Person', 'superclasses': ['NSObject'],
                  'fields': {'name': 'Bob', 'age': 29, 'friend': {'backref': alice_index}}}
bob_in_crowd = {'object': 'Person', 'superclasses': ['NSObject'], 'fields': {
    'name': 'Bob', 'age': 29, 'friend': {'object': 'Person', 'superclasses': ['NSObject'], 'fields': {
        'name': 'Alice', 'age': 31, 'friend': {'backref': bob_index}, 'self': {'backref': alice_index}}}}}
truth['graph.bplist'] = {'top': {
    'root': {'object': 'Person', 'superclasses': ['NSObject'], 'fields': {
        'name': 'Alice', 'age': 31, 'friend': bob_from_alice, 'self': {'backref': alice_index}}},
    'crowd': {'array': 'NSArray', 'items': [bob_in_crowd, bob_in_crowd]},
}}

broken = Archive()
broken_root = broken.array([broken.string('kept'), plistlib.UID(999)])
broken.write('dangling.bplist', {'root': broken_root})
truth['dangling.bplist'] = {'top': {'root': {'array': 'NSArray', 'items': ['kept', {'dangling': 999}]}}}

with open(os.path.join(out_dir, 'truth.json'), 'w', encoding='utf-8') as handle:
    json.dump(truth, handle, indent=1)
