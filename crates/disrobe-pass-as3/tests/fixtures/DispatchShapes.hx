class DispatchShapes {
	public static function dense(selector:Int):Int {
		return switch (selector) {
			case 0: 10;
			case 1: 20;
			case 2: 30;
			case 3: 40;
			case 4: 50;
			default: -1;
		};
	}

	public static function sparse(selector:Int):Int {
		return switch (selector) {
			case 7: 70;
			case 9: 90;
			default: 0;
		};
	}

	public static function unordered(selector:Int):Int {
		return switch (selector) {
			case 5: 500;
			case 1: 100;
			case 3: 300;
			default: 0;
		};
	}

	public static function shared(token:String):Int {
		return switch (token) {
			case "red" | "green": 1;
			case "blue": 2;
			default: 0;
		};
	}

	public static function inLoop(limit:Int):Int {
		var total:Int = 0;
		for (index in 0...limit) {
			total += switch (index % 3) {
				case 0: 1;
				case 1: 10;
				default: 100;
			};
		}
		return total;
	}

	public static function coalesce(value:Null<Int>, fallback:Int):Int {
		return value ?? fallback;
	}

	static function main():Void {
		var total:Int = 0;
		for (index in 0...10)
			total += dense(index) + sparse(index) + unordered(index) + inLoop(index);
		total += shared("red") + shared("blue") + shared("teal");
		total += coalesce(null, 7) + coalesce(3, 7);
		trace(total);
	}
}
