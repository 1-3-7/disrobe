<script type="text/javascript">
<!--

function jjencode( gv, text )
{
    var r="";
    var n;
    var t;
    var b=[ "___", "__$", "_$_", "_$$", "$__", "$_$", "$$_", "$$$", "$___", "$__$", "$_$_", "$_$$", "$$__", "$$_$", "$$$_", "$$$$", ];
    var s = "";
    for( var i = 0; i < text.length; i++ ){
        n = text.charCodeAt( i );
        if( n == 0x22 || n == 0x5c ){
            s += "\\\\\\" + text.charAt( i ).toString(16);
        }else if( (0x21 <= n && n <= 0x2f) || (0x3A <= n && n <= 0x40) || ( 0x5b <= n && n <= 0x60 ) || ( 0x7b <= n && n <= 0x7f ) ){

            s += text.charAt( i );
        }else if( (0x30 <= n && n <= 0x39 ) || (0x61 <= n && n <= 0x66 ) ){
            if( s ) r += "\"" + s +"\"+";
            r += gv + "." + b[ n < 0x40 ? n - 0x30 : n - 0x57 ] + "+";
            s="";
        }else if( n == 0x6c ){
            if( s ) r += "\"" + s + "\"+";
            r += "(![]+\"\")[" + gv + "._$_]+";
            s = "";
        }else if( n == 0x6f ){
            if( s ) r += "\"" + s + "\"+";
            r += gv + "._$+";
            s = "";
        }else if( n == 0x74 ){
            if( s ) r += "\"" + s + "\"+";
            r += gv + ".__+";
            s = "";
        }else if( n == 0x75 ){
            if( s ) r += "\"" + s + "\"+";
            r += gv + "._+";
            s = "";
        }else if( n < 128 ){
            if( s ) r += "\"" + s;
            else r += "\"";
            r += "\\\\\"+" + n.toString( 8 ).replace( /[0-7]/g, function(c){ return gv + "."+b[ c ]+"+" } );
            s = "";
        }else{
            if( s ) r += "\"" + s;
            else r += "\"";
            r += "\\\\\"+" + gv + "._+" + n.toString(16).replace( /[0-9a-f]/gi, function(c){ return gv + "."+b[parseInt(c,16)]+"+"} );
            s = "";
        }
    }
    if( s ) r += "\"" + s + "\"+";

    r =
    gv + "=~[];" +
    gv + "={___:++" + gv +",$$$$:(![]+\"\")["+gv+"],__$:++"+gv+",$_$_:(![]+\"\")["+gv+"],_$_:++"+
    gv+",$_$$:({}+\"\")["+gv+"],$$_$:("+gv+"["+gv+"]+\"\")["+gv+"],_$$:++"+gv+",$$$_:(!\"\"+\"\")["+
    gv+"],$__:++"+gv+",$_$:++"+gv+",$$__:({}+\"\")["+gv+"],$$_:++"+gv+",$$$:++"+gv+",$___:++"+gv+",$__$:++"+gv+"};"+
    gv+".$_="+
    "("+gv+".$_="+gv+"+\"\")["+gv+".$_$]+"+
    "("+gv+"._$="+gv+".$_["+gv+".__$])+"+
    "("+gv+".$$=("+gv+".$+\"\")["+gv+".__$])+"+
    "((!"+gv+")+\"\")["+gv+"._$$]+"+
    "("+gv+".__="+gv+".$_["+gv+".$$_])+"+
    "("+gv+".$=(!\"\"+\"\")["+gv+".__$])+"+
    "("+gv+"._=(!\"\"+\"\")["+gv+"._$_])+"+
    gv+".$_["+gv+".$_$]+"+
    gv+".__+"+
    gv+"._$+"+
    gv+".$;"+
    gv+".$$="+
    gv+".$+"+
    "(!\"\"+\"\")["+gv+"._$$]+"+
    gv+".__+"+
    gv+"._+"+
    gv+".$+"+
    gv+".$$;"+
    gv+".$=("+gv+".___)["+gv+".$_]["+gv+".$_];"+
    gv+".$("+gv+".$("+gv+".$$+\"\\\"\"+" + r + "\"\\\"\")())();";

    return r;
}

var _prev;

function keyup( force )
{
    var t = document.getElementById( "src" ).value;
    var v = document.getElementById( "var" ).value || "$";
	var p = document.getElementById( "palindrome" ).checked;
	var r;

    if( _prev != ( t + "\0" + v + "\0" + p ) || force ){
		r = jjencode( v, t );
		if( p ){
			r = r.replace( /[,;]$/, "" );
			r = "\"\'\\\"+\'+\"," + r + ",\'," + r.split("").reverse().join("") +",\"+\'+\"\\\'\"";
		}
		document.getElementById("dst").value = r;
		document.getElementById("letters").innerHTML = r.length;
        _prev = t + "\0" + v;
        document.getElementById( "permalink").setAttribute( "href",
            location.href.replace( /\?.*$/, "" ) + "?src=" + encodeURIComponent( t ) + "&var=" + encodeURIComponent( v ) + ( p ? "&p=1" : "" ) ) ;
    }
}

function init()
{
    var q = document.location.search && document.location.search.substring( 1 ).split( "&" );
    for( var i = 0; i < q.length; i++ ){
        if( q[ i ].substring( 0, 4 ) == "src=" ){
            document.getElementById( "src" ).value = decodeURIComponent( q[ i ].substring( 4 ) );
        }else if( q[ i ].substring( 0, 4 ) == "var=" ){
            document.getElementById( "var" ).value = decodeURIComponent( q[ i ].substring( 4 ) );
        }else if( q[ i ].substring( 0, 2 ) == "p=" ){
            document.getElementById( "palindrome" ).checked = q[ i ].substring( 2 ).valueOf() == 1;
        }

    }
    keyup( true );
    document.getElementById( 'src' ).focus();
}
-->
</script>
