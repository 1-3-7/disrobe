<script type="text/javascript">
<!--

function aaencode( text )
{
    var t;
    var b = [
		"(c^_^o)",
		"(ﾟΘﾟ)",
		"((o^_^o) - (ﾟΘﾟ))",
		"(o^_^o)",
		"(ﾟｰﾟ)",
		"((ﾟｰﾟ) + (ﾟΘﾟ))",
		"((o^_^o) +(o^_^o))",
		"((ﾟｰﾟ) + (o^_^o))",
		"((ﾟｰﾟ) + (ﾟｰﾟ))",
		"((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))",
		"(ﾟДﾟ) .ﾟωﾟﾉ",
		"(ﾟДﾟ) .ﾟΘﾟﾉ",
		"(ﾟДﾟ) ['c']",
		"(ﾟДﾟ) .ﾟｰﾟﾉ",
		"(ﾟДﾟ) .ﾟДﾟﾉ",
		"(ﾟДﾟ) [ﾟΘﾟ]"
        ];
	var r = "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); ";

	if( /ひだまりスケッチ×(365|３５６)\s*来週も見てくださいね[!！]/.test( text ) ){
		r += "X=_=3; ";
		r += "\r\n\r\n    X / _ / X < \"来週も見てくださいね!\";\r\n\r\n";
	}
    r += "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);"+
        "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] "+
        ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] "+
        ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];"+
        "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];"+
        "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];"+
        "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + "+
        "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+"+
        "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+"+
        "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+"+
        "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];"+
        "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+"+
        "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+"+
        "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; "+
        "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; "+
        "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];"+
		"(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];"+
        "(ﾟДﾟ) [ﾟoﾟ]='\\\"';"+
        "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+";
    r += "(ﾟДﾟ)[ﾟoﾟ]+ ";
    for( var i = 0; i < text.length; i++ ){
        n = text.charCodeAt( i );
        t = "(ﾟДﾟ)[ﾟεﾟ]+";
		if( n <= 127 ){
			t += n.toString( 8 ).replace( /[0-7]/g, function(c){ return b[ c ] + "+ "; } );
		}else{
			var m = /[0-9a-f]{4}$/.exec( "000" + n.toString(16 ) )[0];
			t += "(oﾟｰﾟo)+ " + m.replace( /[0-9a-f]/gi, function(c){ return b[ parseInt( c,16 ) ] + "+ "; } );
		}
        r += t;

    }
    r += "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');";
    return r;


}

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
        }else if( (0x20 <= n && n <= 0x2f) || (0x3A <= n == 0x40) || ( 0x5b <= n && n <= 0x60 ) || ( 0x7b <= n && n <= 0x7f ) ){
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
    var d;
    if( _prev != ( t ) || force ){
        d = aaencode( t );
        document.getElementById("dst").value= d;
        _prev = t;
        document.getElementById( "permalink").setAttribute( "href",
            location.href.replace( /\?.*$/, "" ) + "?src=" + encodeURIComponent( t ) );
        document.getElementById( "eval").setAttribute( "href", "javascript:" + d );
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
        }

    }
    keyup( true );
    document.getElementById( 'src' ).focus();
}
-->
</script>
