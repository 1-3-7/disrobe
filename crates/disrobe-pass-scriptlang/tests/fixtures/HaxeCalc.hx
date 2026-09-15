class Calculator {
    public var label:String;

    public function new(label:String) {
        this.label = label;
    }

    public function add(a:Int, b:Int):Int {
        return a + b;
    }

    public function describe():String {
        return "Calculator: " + this.label;
    }
}

class Main {
    static function main() {
        var calc = new Calculator("disrobe-demo");
        var sum = calc.add(21, 21);
        trace(calc.describe());
        trace("Sum is " + sum);
    }
}
