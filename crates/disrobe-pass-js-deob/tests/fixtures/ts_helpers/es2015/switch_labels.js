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
function answer(kind) {
    return Promise.resolve(kind.charCodeAt(0));
}
function route(kind) {
    return __awaiter(this, void 0, void 0, function* () {
        let result = "";
        switch (kind) {
            case "a":
                result = "alpha " + (yield answer(kind));
                break;
            case "b":
                result = "beta";
                break;
            default:
                result = "other " + (yield answer(kind));
        }
        return result;
    });
}
function labelled(grid) {
    return __awaiter(this, void 0, void 0, function* () {
        const found = [];
        outer: for (let row = 0; row < grid.length; row++) {
            for (let col = 0; col < grid[row].length; col++) {
                const cell = yield Promise.resolve(grid[row][col]);
                if (cell === 0) {
                    continue outer;
                }
                if (cell < 0) {
                    break outer;
                }
                found.push(row + "." + col + "=" + cell);
            }
        }
        return found.join(" ");
    });
}
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(yield route("a"));
        console.log(yield route("b"));
        console.log(yield route("z"));
        console.log(yield labelled([[1, 2], [0, 3], [4, -1, 5], [6]]));
    });
}
main();
