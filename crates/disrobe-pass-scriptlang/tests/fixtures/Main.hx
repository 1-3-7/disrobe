class Main {
    static function greet(name:String):String {
        return "Hello, " + name + "!";
    }
    static function add(a:Int, b:Int):Int {
        return a + b;
    }
    static function main():Void {
        trace(greet("disrobe"));
        trace(add(2, 3));
    }
}
