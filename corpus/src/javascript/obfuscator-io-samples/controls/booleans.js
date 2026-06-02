const a0_0x2ce4b0 = a0_0x5268;
(function (_0x32a2f5, _0x57a0e6) {
    const _0x46fb27 = a0_0x5268;
    const _0x496e31 = _0x32a2f5();
    while (!![]) {
        try {
            const _0x5915ce = -parseInt(_0x46fb27(0x10f)) / 0x1 * (parseInt(_0x46fb27(0xfd)) / 0x2) + parseInt(_0x46fb27(0x102)) / 0x3 + -parseInt(_0x46fb27(0x103)) / 0x4 + parseInt(_0x46fb27(0x109)) / 0x5 * (parseInt(_0x46fb27(0x108)) / 0x6) + parseInt(_0x46fb27(0x101)) / 0x7 * (-parseInt(_0x46fb27(0x10b)) / 0x8) + -parseInt(_0x46fb27(0x10a)) / 0x9 * (-parseInt(_0x46fb27(0x114)) / 0xa) + parseInt(_0x46fb27(0x112)) / 0xb * (parseInt(_0x46fb27(0x10e)) / 0xc);
            if (_0x5915ce === _0x57a0e6) {
                break;
            } else {
                _0x496e31['push'](_0x496e31['shift']());
            }
        } catch (_0x5c7489) {
            _0x496e31['push'](_0x496e31['shift']());
        }
    }
}(a0_0x2737, 0xb6541));
function add(_0x39a264, _0x1a3685) {
    return _0x39a264 + _0x1a3685;
}
function subtract(_0x375237, _0x103333) {
    return _0x375237 - _0x103333;
}
function multiply(_0xa66644, _0x439167) {
    return _0xa66644 * _0x439167;
}
function divide(_0x29b85c, _0x31e059) {
    const _0x4d6a6b = a0_0x5268;
    if (_0x31e059 === 0x0) {
        throw new Error(_0x4d6a6b(0x10d));
    }
    return _0x29b85c / _0x31e059;
}
function calculate(_0x480b1f, _0xa7725f, _0x4ac90b) {
    const _0x399e7c = a0_0x5268;
    switch (_0x480b1f) {
    case _0x399e7c(0x106):
        return add(_0xa7725f, _0x4ac90b);
    case 'sub':
        return subtract(_0xa7725f, _0x4ac90b);
    case _0x399e7c(0x113):
        return multiply(_0xa7725f, _0x4ac90b);
    case 'div':
        return divide(_0xa7725f, _0x4ac90b);
    default:
        throw new Error(_0x399e7c(0x10c) + _0x480b1f);
    }
}
function greet(_0x4e4bb8) {
    const _0x3037a2 = a0_0x5268;
    const _0x5cf4d5 = _0x3037a2(0x111);
    return _0x5cf4d5 + _0x3037a2(0x110) + _0x4e4bb8;
}
function runSamples() {
    const _0x1670d5 = a0_0x5268;
    const _0x133a6c = [
        [
            _0x1670d5(0x106),
            0xa,
            0x5
        ],
        [
            _0x1670d5(0x100),
            0xa,
            0x5
        ],
        [
            _0x1670d5(0x113),
            0xa,
            0x5
        ],
        [
            _0x1670d5(0xfe),
            0xa,
            0x5
        ]
    ];
    const _0x4595c7 = [];
    for (const [_0x84446b, _0x30ac0b, _0x35f9d4] of _0x133a6c) {
        _0x4595c7[_0x1670d5(0x105)](_0x84446b + '(' + _0x30ac0b + ',' + _0x35f9d4 + _0x1670d5(0xff) + calculate(_0x84446b, _0x30ac0b, _0x35f9d4));
    }
    return _0x4595c7;
}
console[a0_0x2ce4b0(0x104)](greet(a0_0x2ce4b0(0x107)));
function a0_0x5268(_0x1e22be, _0x15d3e3) {
    _0x1e22be = _0x1e22be - 0xfd;
    const _0x2737df = a0_0x2737();
    let _0x52688b = _0x2737df[_0x1e22be];
    return _0x52688b;
}
runSamples()['forEach'](_0x1fe8d6 => console[a0_0x2ce4b0(0x104)](_0x1fe8d6));
function a0_0x2737() {
    const _0x2dc7f5 = [
        'mul',
        '14135060NfwgEx',
        '194rhvmii',
        'div',
        ')\x20=\x20',
        'sub',
        '7000777SAkBFq',
        '138894rkKoHm',
        '5106688HyKUzs',
        'log',
        'push',
        'add',
        'disrobe',
        '12AldZZH',
        '2930535IQpxdw',
        '9SMlDpJ',
        '8HBwfoB',
        'unknown\x20op:\x20',
        'divide\x20by\x20zero',
        '17568JzFWKu',
        '13682WjCnxC',
        '\x20::\x20hello,\x20',
        'calculator\x20ready',
        '12914BYOjbR'
    ];
    a0_0x2737 = function () {
        return _0x2dc7f5;
    };
    return a0_0x2737();
}
