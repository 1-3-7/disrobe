(function (mathUtils, format) {
    'use strict';

    globalThis.__result = [
        format(mathUtils.sum(20, 22)),
        format(mathUtils.sum(1, 2)),
        format(mathUtils.sum(3, 4)),
        format(mathUtils.sum(5, 6)),
        format(mathUtils.sum(7, 8)),
        format(mathUtils.sum(9, 10)),
        format(mathUtils.sum(11, 12)),
        format(mathUtils.sum(13, 14)),
    ].join("|");

})(globalThis.MathUtils, globalThis.TextFormat);
