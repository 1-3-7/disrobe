class WhitespaceShortCircuit {
    static function isWhiteSpace(c:String):Bool {
        return c == " " || c == "\t" || c == "\n" || c == "\r";
    }

    static function main():Void {
        trace(isWhiteSpace("x"));
    }
}
