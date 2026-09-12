import { sum } from "@fixture/math-utils";
import format from "@fixture/text-format";

globalThis.__result = format(sum(20, 22));
