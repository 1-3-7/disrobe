class SwitchMerge {
    static function choose(selector:Int):Int {
        var value:Int = switch (selector) {
            case 0: 10;
            case 1: 20;
            case 2: 30;
            default: 40;
        };
        return value + 1;
    }

    static function main():Void {
        trace(choose(1));
    }
}
