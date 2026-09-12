System.register(['@fixture/math-utils', '@fixture/text-format'], (function () {
	'use strict';
	var sum, format;
	return {
		setters: [function (module) {
			sum = module.sum;
		}, function (module) {
			format = module.default;
		}],
		execute: (function () {

			globalThis.__result = format(sum(20, 22));

		})
	};
}));
