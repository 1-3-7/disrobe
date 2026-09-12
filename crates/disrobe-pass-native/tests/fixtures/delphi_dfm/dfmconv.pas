program dfmconv;

{$MODE OBJFPC}
{$H+}

uses
  Classes, SysUtils;

var
  Mode: string;
  Input: TFileStream;
  Output: TFileStream;

procedure TextError(const Message: string; Line: Integer);
begin
  WriteLn(StdErr, 'parse error on line ', Line, ': ', Message);
  Halt(3);
end;

begin
  if ParamCount <> 3 then
  begin
    WriteLn(StdErr, 'usage: dfmconv <b2t|t2b> <input> <output>');
    Halt(2);
  end;
  Mode := ParamStr(1);
  Input := TFileStream.Create(ParamStr(2), fmOpenRead or fmShareDenyNone);
  try
    Output := TFileStream.Create(ParamStr(3), fmCreate);
    try
      if Mode = 'b2t' then
        ObjectBinaryToText(Input, Output)
      else if Mode = 't2b' then
        ObjectTextToBinary(Input, Output)
      else
      begin
        WriteLn(StdErr, 'unknown mode: ', Mode);
        Halt(2);
      end;
    finally
      Output.Free;
    end;
  finally
    Input.Free;
  end;
end.
