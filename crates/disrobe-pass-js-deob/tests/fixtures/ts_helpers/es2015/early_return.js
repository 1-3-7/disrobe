"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const cache = {};
function fetchValue(key) {
    return Promise.resolve(key.length * 7);
}
function lookup(key) {
    return __awaiter(this, void 0, void 0, function* () {
        if (key in cache) {
            return cache[key];
        }
        if (key === "") {
            return -1;
        }
        const value = yield fetchValue(key);
        if (value > 20) {
            cache[key] = value;
            return value;
        }
        const doubled = yield fetchValue(key + key);
        return doubled;
    });
}
function classify(value) {
    return __awaiter(this, void 0, void 0, function* () {
        if (value < 0) {
            return "negative";
        }
        else if (value === 0) {
            yield Promise.resolve();
            return "zero";
        }
        const scaled = yield Promise.resolve(value * 10);
        return scaled > 50 ? "large" : "small";
    });
}
function nothing(flag) {
    return __awaiter(this, void 0, void 0, function* () {
        if (flag) {
            return;
        }
        yield Promise.resolve();
        console.log("nothing continued");
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield lookup("abc"));
        console.log(yield lookup("abcd"));
        console.log(yield lookup("abcd"));
        console.log(yield lookup(""));
        console.log(yield lookup("a"));
        console.log(yield classify(-3));
        console.log(yield classify(0));
        console.log(yield classify(2));
        console.log(yield classify(9));
        yield nothing(true);
        yield nothing(false);
    });
}
main();
