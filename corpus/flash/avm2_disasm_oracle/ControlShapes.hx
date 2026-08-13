class ControlShapes {
	static function labelled(rows:Int, columns:Int):Int {
		var total:Int = 0;
		var stopped:Bool = false;
		for (row in 0...rows) {
			if (stopped)
				break;
			for (column in 0...columns) {
				if (column == 2)
					continue;
				if (row * column > 12) {
					stopped = true;
					break;
				}
				total += row * column;
			}
		}
		return total;
	}

	static function words(token:String):Int {
		return switch (token) {
			case "alpha": 1;
			case "beta": 2;
			case "gamma": 3;
			case "delta" | "epsilon": 4;
			default: 0;
		};
	}

	static function guarded(value:Int):String {
		var outcome:String = "none";
		try {
			if (value < 0)
				throw new CustomFault("negative");
			if (value == 0)
				throw "zero";
			outcome = "positive";
		} catch (fault:CustomFault) {
			outcome = fault.reason;
		} catch (text:String) {
			outcome = text;
		} catch (rest:Dynamic) {
			outcome = Std.string(rest);
		}
		return outcome;
	}

	static function recurse(depth:Int, accumulator:Int):Int {
		if (depth <= 0)
			return accumulator;
		return recurse(depth - 1, accumulator + depth);
	}

	static function ternaries(a:Int, b:Int):Int {
		var pick:Int = a > b ? a : b;
		var clamp:Int = pick > 10 ? 10 : (pick < 0 ? 0 : pick);
		return pick + clamp + (a == b ? 1 : (a < b ? 2 : 3));
	}

	static function shortCircuit(left:Bool, right:Bool, value:Int):Bool {
		return (left && value > 3) || (right && value < 9) || (!left && !right);
	}

	static function tables(size:Int):Int {
		var lookup:Map<String, Int> = new Map<String, Int>();
		lookup.set("one", 1);
		lookup.set("two", 2);
		var total:Int = 0;
		for (key in lookup.keys())
			total += lookup.get(key);
		var rows:Array<Array<Int>> = [];
		for (index in 0...size)
			rows.push([index, index * 2]);
		for (row in rows)
			for (cell in row)
				total += cell;
		return total;
	}

	static function enums(shape:Shape):Int {
		return switch (shape) {
			case Point: 0;
			case Line(length): length;
			case Box(width, height): width * height;
		};
	}

	static function main():Void {
		var total:Int = 0;
		total += labelled(5, 4);
		total += words("gamma");
		total += guarded(-1).length;
		total += guarded(0).length;
		total += guarded(7).length;
		total += recurse(6, 0);
		total += ternaries(4, 9);
		total += shortCircuit(true, false, 5) ? 1 : 0;
		total += tables(3);
		total += enums(Box(2, 3));
		total += enums(Line(4));
		trace(total);
	}
}

class CustomFault {
	public var reason:String;

	public function new(reason:String) {
		this.reason = reason;
	}
}

enum Shape {
	Point;
	Line(length:Int);
	Box(width:Int, height:Int);
}
