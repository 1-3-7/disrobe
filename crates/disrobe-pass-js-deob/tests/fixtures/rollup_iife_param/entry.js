import { sum } from "@fixture/math-utils";
import format from "@fixture/text-format";

globalThis.__result = [
    format(sum(20, 22)),
    format(sum(1, 2)),
    format(sum(3, 4)),
    format(sum(5, 6)),
    format(sum(7, 8)),
    format(sum(9, 10)),
    format(sum(11, 12)),
    format(sum(13, 14)),
].join("|");
