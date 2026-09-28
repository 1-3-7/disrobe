class JunkAfterJump {
    static function pick(n:Int):Int {
        var total = 0;
        for (i in 0...n) {
            if (i % 3 == 0) {
                total += i;
                continue;
            }
            total -= 1;
        }
        return total;
    }

    static function main():Void {
        trace(pick(10));
    }
}
