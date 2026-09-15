class OpcodeBreadth {
	static var tally:Int = 0;
	static var scale:Float = 1.5;

	static function arithmetic(a:Float, b:Float):Float {
		var product:Float = a * b;
		var quotient:Float = a / b;
		var remainder:Float = a % b;
		var negated:Float = -a;
		var difference:Float = product - quotient;
		return product + quotient + remainder + negated + difference;
	}

	static function bitwise(a:Int, b:Int):Int {
		var disjunction:Int = a | b;
		var exclusive:Int = a ^ b;
		var inverted:Int = ~a;
		var left:Int = a << 3;
		var arithmeticRight:Int = a >> 2;
		var logicalRight:Int = a >>> 4;
		var product:Int = a * b;
		var negated:Int = -a;
		return disjunction + exclusive + inverted + left + arithmeticRight + logicalRight + product + negated;
	}

	static function comparisons(a:Float, b:Float):Int {
		var score:Int = 0;
		if (a <= b)
			score++;
		if (a >= b)
			score++;
		if (a > b)
			score++;
		if (a < b)
			score++;
		if (a == b)
			score++;
		if (a != b)
			score++;
		return score;
	}

	static function typing(value:Dynamic):String {
		if (Std.isOfType(value, String))
			return "string";
		if (Std.isOfType(value, Array))
			return "array";
		var kind:String = untyped __typeof__(value);
		var cast_result:Dynamic = untyped __as__(value, String);
		if (cast_result != null)
			return kind + "-string";
		return kind;
	}

	static function membership(holder:Dynamic):Int {
		var found:Int = 0;
		if (untyped __in__("alpha", holder))
			found++;
		if (untyped __in__("beta", holder))
			found++;
		untyped __delete__(holder, "alpha");
		return found;
	}

	static function iterate(source:Array<Int>):Int {
		var total:Int = 0;
		for (item in source)
			total += item;
		var record:Dynamic = {alpha: 1, beta: 2, gamma: 3};
		for (name in Reflect.fields(record))
			total += name.length;
		var keys:Array<String> = untyped __keys__(record);
		total += keys.length;
		return total;
	}

	static function exceptions(flag:Bool):String {
		try {
			if (flag)
				throw "boom";
			return "clear";
		} catch (message:String) {
			return message;
		} catch (other:Dynamic) {
			return Std.string(other);
		}
	}

	static function closure(seed:Int):Int->Int {
		var captured:Int = seed;
		var step:Int->Int = function(delta:Int):Int {
			captured += delta;
			return captured;
		};
		captured += 1;
		return step;
	}

	static function constants():Array<Dynamic> {
		var tiny:Int = 7;
		var short:Int = 3000;
		var wide:Int = 70000;
		var fraction:Float = 2.5;
		var notANumber:Float = Math.NaN;
		var nothing:Dynamic = null;
		return [tiny, short, wide, fraction, notANumber, nothing, true, false, "text"];
	}

	static function memory():Int {
		var buffer:flash.utils.ByteArray = new flash.utils.ByteArray();
		buffer.length = 4096;
		flash.Memory.select(buffer);
		flash.Memory.setByte(0, 42);
		flash.Memory.setI16(2, 3000);
		flash.Memory.setI32(4, 70000);
		flash.Memory.setFloat(8, 1.5);
		flash.Memory.setDouble(16, 2.5);
		var total:Int = flash.Memory.getByte(0) + flash.Memory.getUI16(2) + flash.Memory.getI32(4);
		total += Std.int(flash.Memory.getFloat(8) + flash.Memory.getDouble(16));
		total += flash.Memory.signExtend1(1) + flash.Memory.signExtend8(200) + flash.Memory.signExtend16(40000);
		return total;
	}

	static function vectors():Int {
		var items:flash.Vector<Int> = new flash.Vector<Int>(4);
		items[0] = 1;
		items[1] = 2;
		var total:Int = 0;
		for (index in 0...items.length)
			total += items[index];
		return total;
	}

	static function strings(input:String):String {
		var upper:String = input.toUpperCase();
		var joined:String = upper + "-" + input.length;
		return joined.substr(0, 8);
	}

	static function loops(limit:Int):Int {
		var index:Int = 0;
		var total:Int = 0;
		while (index < limit) {
			total += index;
			index++;
		}
		do {
			total--;
		} while (total > limit);
		for (step in 0...limit)
			total += step;
		return total;
	}

	static function inherited():Int {
		var child:Derived = new Derived(3);
		child.grow();
		return child.describe().length + child.doubled() + child.inflated();
	}

	static function selector(choice:Int):Int {
		return switch (choice) {
			case 0: 11;
			case 3: 22;
			case 9: 33;
			case 17: 44;
			default: 55;
		};
	}

	static function widths():Float {
		var unsigned:UInt = 2000000000;
		var medium:Int = 3000;
		var counter:Float = 1.5;
		counter++;
		counter--;
		var text:String = Std.string(counter) + Std.string(medium);
		var infinite:Float = Math.POSITIVE_INFINITY;
		var undefinedish:Float = Math.NaN;
		var widened:Float = cast unsigned;
		return widened + medium + counter + text.length + (infinite > 0 ? 1 : 0) + (undefinedish != undefinedish ? 2 : 0);
	}

	static function main():Void {
		var accumulate:Int->Int = closure(4);
		tally += accumulate(2);
		tally += Std.int(arithmetic(3.5, 1.25) * scale);
		tally += bitwise(9, 5);
		tally += comparisons(1.5, 2.5);
		tally += typing("probe").length;
		tally += membership({alpha: 1, beta: 2});
		tally += iterate([1, 2, 3]);
		tally += exceptions(true).length;
		tally += constants().length;
		tally += memory();
		tally += vectors();
		tally += strings("probe").length;
		tally += loops(4);
		tally += inherited();
		tally += selector(9);
		tally += Std.int(widths());
		trace(tally);
	}
}

class Base {
	public var size:Int;

	public function new(size:Int) {
		this.size = size;
	}

	public function describe():String {
		return "base" + size;
	}

	public function doubled():Int {
		return size * 2;
	}

	public function reset():Void {
		size = 0;
	}
}

class Derived extends Base {
	public function new(size:Int) {
		super(size + 1);
	}

	override public function describe():String {
		return "derived:" + super.describe();
	}

	override public function doubled():Int {
		return super.doubled() + 1;
	}

	public function grow():Void {
		size = size + 2;
		super.reset();
	}

	public function inflated():Int {
		return size * 3;
	}
}
