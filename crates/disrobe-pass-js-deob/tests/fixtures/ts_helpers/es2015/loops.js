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
function tick(value) {
    return new Promise((resolve) => setTimeout(() => resolve(value), 0));
}
function sumRange(limit) {
    return __awaiter(this, void 0, void 0, function* () {
        let total = 0;
        for (let index = 0; index < limit; index++) {
            total += yield tick(index);
        }
        return total;
    });
}
function countDown(start) {
    return __awaiter(this, void 0, void 0, function* () {
        const seen = [];
        let current = start;
        while (current > 0) {
            seen.push(yield tick(current));
            current -= 2;
        }
        return seen.join(",");
    });
}
function doWhile() {
    return __awaiter(this, void 0, void 0, function* () {
        let rounds = 0;
        do {
            rounds = yield tick(rounds + 1);
        } while (rounds < 4);
        return rounds;
    });
}
function overArray(items) {
    return __awaiter(this, void 0, void 0, function* () {
        let out = "";
        for (const item of items) {
            out += (yield Promise.resolve(item)).toUpperCase();
        }
        return out;
    });
}
function skipAndStop(values) {
    return __awaiter(this, void 0, void 0, function* () {
        let total = 0;
        for (let index = 0; index < values.length; index++) {
            const value = yield tick(values[index]);
            if (value < 0) {
                continue;
            }
            if (value > 100) {
                break;
            }
            total += value;
        }
        return total;
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield sumRange(5));
        console.log(yield countDown(7));
        console.log(yield doWhile());
        console.log(yield overArray(["a", "b", "c"]));
        console.log(yield skipAndStop([1, -2, 3, 400, 5]));
    });
}
main();
