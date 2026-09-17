class JsonTokenizer {
    static function nextChar(chars:Array<String>, index:Int):String {
        return chars[index++];
    }

    static function main():Void {
        trace(nextChar(["a", "b"], 0));
    }
}
