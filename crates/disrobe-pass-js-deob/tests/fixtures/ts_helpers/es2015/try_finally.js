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
const log = [];
function settle(ok, value) {
    return ok ? Promise.resolve(value) : Promise.reject(new Error(value));
}
function guarded(ok) {
    return __awaiter(this, void 0, void 0, function* () {
        log.push("enter " + ok);
        try {
            const value = yield settle(ok, "v" + ok);
            log.push("got " + value);
            return value;
        }
        catch (error) {
            log.push("caught " + error.message);
            return "fallback";
        }
        finally {
            log.push("finally " + ok);
        }
    });
}
function cleanup() {
    return __awaiter(this, void 0, void 0, function* () {
        let count = 0;
        try {
            count += yield Promise.resolve(1);
            try {
                count += yield Promise.resolve(10);
                yield settle(false, "inner");
            }
            finally {
                count += 100;
                log.push("inner finally " + count);
            }
        }
        catch (error) {
            log.push("outer caught " + error.message);
            count += yield Promise.resolve(1000);
        }
        return count;
    });
}
function finallyAwait() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            return yield settle(true, "body");
        }
        finally {
            yield Promise.resolve(0);
            log.push("awaited in finally");
        }
    });
}
function rethrow() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            yield settle(false, "boom");
        }
        catch (error) {
            log.push("rethrowing " + error.message);
            throw new Error("again " + error.message);
        }
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield guarded(true));
        console.log(yield guarded(false));
        console.log(yield cleanup());
        console.log(yield finallyAwait());
        try {
            yield rethrow();
        }
        catch (error) {
            console.log("main caught " + error.message);
        }
        console.log(log.join(";"));
    });
}
main();
