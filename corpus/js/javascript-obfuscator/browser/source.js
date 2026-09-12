function detect() {
    var ua = String(navigator.userAgent);
    var flags = [];
    if (typeof window !== "undefined") {
        flags.push("win");
    }
    if (typeof document.querySelector === "function") {
        flags.push("qs");
    }
    flags.push("ualen=" + ua.length);
    return flags.join("|");
}

function score(n) {
    var total = 0;
    for (var i = 1; i <= n; i++) {
        total += i * i;
    }
    return total;
}

function classify(v) {
    if (v > 50) {
        return "high";
    }
    if (v > 10) {
        return "mid";
    }
    return "low";
}

var loc = String(window.location.pathname);
var s = score(6);
console.log(detect());
console.log("score=" + s + ";class=" + classify(s));
console.log("loc=" + loc + ";empty=" + (loc.length === 0));
console.log("screen=" + String(screen.width));
document.title = "ready";
console.log("done");
