unit DCPtea;

{$MODE Delphi}

interface

uses
  Classes, Sysutils, Crypto;

type

  { TCipherTEA }

  TCipherTEA= class(TCipher)
  protected
    KeyData: array[0..3] of dword;
    procedure InitKey(const Key; Size: longword); override;
  public
    destructor Destroy; override;
    class function Algorithm: TCipherAlgorithm; override;
    class function BlockSize: Integer; override;
    class function MaxKeySize: integer; override;
    class function SelfTest: boolean; override;
    procedure EncryptBlock(const InData; var OutData); override;
    procedure DecryptBlock(const InData; var OutData); override;
  end;

implementation
{$R-}{$Q-}

const
  Delta: DWord = $9e3779b9;
  Rounds= 32;

function SwapDword(a: dword): dword;
begin
  Result:= ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

class function TCipherTEA.Algorithm: TCipherAlgorithm;
begin
  Result:= caTEA;
end;

class function TCipherTEA.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherTEA.MaxKeySize: integer;
begin
  Result:= 128;
end;

class function TCipherTEA.SelfTest: boolean;
const
  Key: array[0..3] of dword= ($12345678,$9ABCDEF0,$0FEDCBA9,$87654321);
  PT: array[0..1] of dword= ($12345678,$9ABCDEF0);
var
  Data: array[0..1] of dword;
  Cipher: TCipherTEA;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher := TCipherTEA.Create(@Key,Sizeof(Key)*8);
  Cipher.EncryptBlock(PT,Data);
  Result:= not CompareMem(@Data,@PT,Sizeof(PT));
  Cipher.DecryptBlock(Data,Data);
  Result:= Result and CompareMem(@Data,@PT,Sizeof(PT));
  Cipher.Free;
end;

procedure TCipherTEA.InitKey(const Key; Size: longword);
begin
  FillChar(KeyData,Sizeof(KeyData),0);
  Move(Key,KeyData,Size div 8);
  KeyData[0]:= SwapDWord(KeyData[0]); KeyData[1]:= SwapDWord(KeyData[1]);
  KeyData[2]:= SwapDWord(KeyData[2]); KeyData[3]:= SwapDWord(KeyData[3]);
end;

destructor TCipherTEA.Destroy;
begin
  FillChar(KeyData,Sizeof(KeyData),0);
  inherited Destroy;
end;

procedure TCipherTEA.EncryptBlock(const InData; var OutData);
var
  a, b, c, d, x, y, n, sum: dword;
begin
  x:= SwapDWord(pdword(@InData)^);
  y:= SwapDWord(pdword(pointer(@InData)+4)^);
  sum:= 0; a:= KeyData[0]; b:= KeyData[1]; c:= KeyData[2]; d:= KeyData[3];
  for n:= 1 to Rounds do
  begin
    Inc(sum,Delta);
    Inc(x,(y shl 4) + (a xor y) + (sum xor (y shr 5)) + b);
    Inc(y,(x shl 4) + (c xor x) + (sum xor (x shr 5)) + d);
  end;
  pdword(@OutData)^:= SwapDWord(x);
  pdword(pointer(@OutData)+4)^:= SwapDWord(y);
end;

procedure TCipherTEA.DecryptBlock(const InData; var OutData);
var
  a, b, c, d, x, y, n, sum: dword;
begin
  x:= SwapDWord(pdword(@InData)^);
  y:= SwapDWord(pdword(pointer(@InData)+4)^);
  sum:= Delta shl 5;
  a:= KeyData[0];
  b:= KeyData[1];
  c:= KeyData[2];
  d:= KeyData[3];
  for n:= 1 to Rounds do
  begin
    Dec(y,(x shl 4) + (c xor x) + (sum xor (x shr 5)) + d);
    Dec(x,(y shl 4) + (a xor y) + (sum xor (y shr 5)) + b);
    Dec(sum,Delta);
  end;
  pdword(@OutData)^:= SwapDWord(x);
  pdword(pointer(@OutData)+4)^:= SwapDWord(y);
end;

end.