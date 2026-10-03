-- Lua 5.3+ / Luau compatibility polyfills
if not math.ldexp then math.ldexp = function(x, n) return x * 2 ^ n end end
if not math.frexp then math.frexp = function(x)
    if x == 0 then return 0, 0 end
    local exp = math.floor(math.log(math.abs(x)) / math.log(2)) + 1
    local mantissa = x / 2 ^ exp
    return mantissa, exp
end end
if not loadstring and load then loadstring = load end
if not loadstring then loadstring = function(s) return load(s) end end

--[Obfuscated by Hercules v2.0.0 | hercules-obfuscator.xyz/discord | hercules-obfuscator.xyz/source]
local XTlKEjDsoe,rhhueLSDajG;XTlKEjDsoe=print;rhhueLSDajG=table.concat;local function VpypyjzqvFUe(d,e,hPptYuzFqKW,a) local fHgESkbhhfS=2;fHgESkbhhfS=((d<d)or e==0)and 17 or(hPptYuzFqKW-a);local sCFfbjeEfQQ=(d>1)and 5 or(a+hPptYuzFqKW);return fHgESkbhhfS,sCFfbjeEfQQ end XTlKEjDsoe(VpypyjzqvFUe(4,5,0,6));XTlKEjDsoe(VpypyjzqvFUe(4,0,0,6));XTlKEjDsoe(VpypyjzqvFUe(0,3,2,1));local function pRcBptGG(a,hPptYuzFqKW,d) hPptYuzFqKW=(d>1)and(hPptYuzFqKW*18)%97 or(a+hPptYuzFqKW);local KIiUcbgsyC=((d==0)and(6<d))and(19-d)or(a-d);return hPptYuzFqKW,KIiUcbgsyC end XTlKEjDsoe(pRcBptGG(3,4,2));XTlKEjDsoe(pRcBptGG(3,4,0));XTlKEjDsoe(pRcBptGG(-1,9,7));local function vgbbVNsz(t,flag,a,d) local hPptYuzFqKW;if flag then t[2]=a+d else hPptYuzFqKW=t[2]or(a+d) end hPptYuzFqKW=(d>1)and(a*18)%97 or(a+(hPptYuzFqKW or 0));return hPptYuzFqKW,t[2] end XTlKEjDsoe(vgbbVNsz({},true,3,4));XTlKEjDsoe(vgbbVNsz({},false,3,4));XTlKEjDsoe(vgbbVNsz({[2]=8},false,3,0));local function QOOezskydWo(p,a,hPptYuzFqKW) local nKmJpXtNe=0;if p then local qTdVYUlH=0;while qTdVYUlH<3 and((a<hPptYuzFqKW)or qTdVYUlH==0)do qTdVYUlH=qTdVYUlH+1;a=a+1;nKmJpXtNe=nKmJpXtNe+qTdVYUlH end else nKmJpXtNe=-1 end return nKmJpXtNe,a end XTlKEjDsoe(QOOezskydWo(true,1,2));XTlKEjDsoe(QOOezskydWo(true,5,2));XTlKEjDsoe(QOOezskydWo(false,1,2));local function MSSKHHWnFw(rows) local URtIedRT={};for i=1,#rows do local sSfuxQtAE=rows[i];if sSfuxQtAE>0 then local qVhszAByhr=0;while qVhszAByhr<sSfuxQtAE and((qVhszAByhr%2==0)or qVhszAByhr==1)do qVhszAByhr=qVhszAByhr+1 end URtIedRT[#URtIedRT+1]=qVhszAByhr else URtIedRT[#URtIedRT+1]=(sSfuxQtAE==0)and 0 or-sSfuxQtAE end end return table.concat(URtIedRT,",") end XTlKEjDsoe(MSSKHHWnFw({3,0,-4,1,6}))