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
class Counter {
    constructor(start) {
        this.value = start;
    }
    increment(step) {
        return __awaiter(this, void 0, void 0, function* () {
            this.value += yield Promise.resolve(step);
            return this.value;
        });
    }
    runMany(steps) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = [];
            for (const step of steps) {
                results.push(yield this.increment(step));
            }
            return results;
        });
    }
    delayedRead() {
        const read = () => __awaiter(this, void 0, void 0, function* () {
            yield Promise.resolve();
            return "value=" + this.value;
        });
        return read();
    }
    static create(start) {
        return __awaiter(this, void 0, void 0, function* () {
            const initial = yield Promise.resolve(start * 2);
            return new Counter(initial);
        });
    }
}
const helpers = {
    base: 5,
    scaled(factor) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.base * (yield Promise.resolve(factor));
        });
    },
};
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        const counter = yield Counter.create(3);
        console.log(yield counter.increment(4));
        console.log((yield counter.runMany([1, 2, 3])).join(","));
        console.log(yield counter.delayedRead());
        console.log(yield helpers.scaled(6));
    });
}
main();
