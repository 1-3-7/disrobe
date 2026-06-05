;(function() {
    var $B = __BRYTHON__;
    $B.imported['hello'] = (function() {
        var $locals_hello = {};
        $locals_hello.greet = function() { return 'hi from brython'; };
        $B.modules['hello'] = $locals_hello;
        return $locals_hello;
    })();
})();
