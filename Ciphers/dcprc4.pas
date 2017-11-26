unit DCPrc4;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, Crypto;

type
  TCipherRC4= class(TCipher)
  protected
    KeyData, KeyOrg: array[0..255] of byte;
  public
    class function Algorithm: TCipherAlgorithm; override;
    class function MaxKeySize: integer; override;
    class function SelfTest: boolean; override;
    procedure Init(const Key; Size: longword; InitVector: pointer); override;
    procedure Reset; override;
    procedure Burn; override;
    procedure Encrypt(const InData; var OutData; Size: longword); override;
    procedure Decrypt(const InData; var OutData; Size: longword); override;
  end;

implementation
{$R-}{$Q-}

class function TCipherRC4.Algorithm: TCipherAlgorithm;
begin
  Result:= caRC4;
end;

class function TCipherRC4.MaxKeySize: integer;
begin
  Result:= 2048;
end;

class function TCipherRC4.SelfTest: boolean;
const
  Key1: array[0..4] of byte= ($61,$8A,$63,$D2,$FB);
  InData1: array[0..4] of byte= ($DC,$EE,$4C,$F9,$2C);
  OutData1: array[0..4] of byte= ($F1,$38,$29,$C9,$DE);
var
  Cipher: TCipherRC4;
  Data: array[0..4] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherRC4.Create;
  Cipher.Init(Key1,Sizeof(Key1)*8,nil);
  Cipher.Encrypt(InData1,Data,Sizeof(Data));
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.Reset;
  Cipher.Decrypt(Data,Data,Sizeof(Data));
  Result:= boolean(CompareMem(@Data,@InData1,Sizeof(Data))) and Result;
  Cipher.Burn;
  Cipher.Free;
end;

procedure TCipherRC4.Init(const Key; Size: longword; InitVector: pointer);
var
  i, j, t: longword;
  xKey: array[0..255] of byte;
begin
  if fInitialized then
    Burn;
  inherited Init(Key,Size,nil);
  Size:= Size div 8;
  i:= 0;
  while i< 255 do
  begin
    KeyData[i]:= i;
    xKey[i]:= PByte(pointer(@Key)+(i mod Size))^;
    KeyData[i+1]:= i+1;
    xKey[i+1]:= PByte(pointer(@Key)+((i+1) mod Size))^;
    KeyData[i+2]:= i+2;
    xKey[i+2]:= PByte(pointer(@Key)+((i+2) mod Size))^;
    KeyData[i+3]:= i+3;
    xKey[i+3]:= PByte(pointer(@Key)+((i+3) mod Size))^;
    KeyData[i+4]:= i+4;
    xKey[i+4]:= PByte(pointer(@Key)+((i+4) mod Size))^;
    KeyData[i+5]:= i+5;
    xKey[i+5]:= PByte(pointer(@Key)+((i+5) mod Size))^;
    KeyData[i+6]:= i+6;
    xKey[i+6]:= PByte(pointer(@Key)+((i+6) mod Size))^;
    KeyData[i+7]:= i+7;
    xKey[i+7]:= PByte(pointer(@Key)+((i+7) mod Size))^;
    Inc(i,8);
  end;
  j:= 0;
  i:= 0;
  while i< 255 do
  begin
    j:= (j+KeyData[i]+xKey[i]) and $FF;
    t:= KeyData[i];
    KeyData[i]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+1]+xKey[i+1]) and $FF;
    t:= KeyData[i+1];
    KeyData[i+1]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+2]+xKey[i+2]) and $FF;
    t:= KeyData[i+2];
    KeyData[i+2]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+3]+xKey[i+3]) and $FF;
    t:= KeyData[i+3];
    KeyData[i+3]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+4]+xKey[i+4]) and $FF;
    t:= KeyData[i+4];
    KeyData[i+4]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+5]+xKey[i+5]) and $FF;
    t:= KeyData[i+5];
    KeyData[i+5]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+6]+xKey[i+6]) and $FF;
    t:= KeyData[i+6];
    KeyData[i+6]:= KeyData[j];
    KeyData[j]:= t;
    j:= (j+KeyData[i+7]+xKey[i+7]) and $FF;
    t:= KeyData[i+7];
    KeyData[i+7]:= KeyData[j];
    KeyData[j]:= t;
    Inc(i,8);
  end;
  Move(KeyData,KeyOrg,Sizeof(KeyOrg));
end;

procedure TCipherRC4.Reset;
begin
  Move(KeyOrg,KeyData,Sizeof(KeyData));
end;

procedure TCipherRC4.Burn;
begin
  FillChar(KeyOrg,Sizeof(KeyOrg),$FF);
  FillChar(KeyData,Sizeof(KeyData),$FF);
  inherited Burn;
end;

procedure TCipherRC4.Encrypt(const InData; var OutData; Size: longword);
var
  i, j, t, k: longword;
begin
  if not fInitialized then
    raise ECipher.Create('Cipher not initialized');
  i:= 0; j:= 0;
  for k:= 0 to Size-1 do
  begin
    i:= (i + 1) and $FF;
    t:= KeyData[i];
    j:= (j + t) and $FF;
    KeyData[i]:= KeyData[j];
    KeyData[j]:= t;
    t:= (t + KeyData[i]) and $FF;
    Pbytearray(@OutData)^[k]:= Pbytearray(@InData)^[k] xor KeyData[t];
  end;
end;

procedure TCipherRC4.Decrypt(const InData; var OutData; Size: longword);
var
  i, j, t, k: longword;
begin
  if not fInitialized then
    raise ECipher.Create('Cipher not initialized');
  i:= 0; j:= 0;
  for k:= 0 to Size-1 do
  begin
    i:= (i + 1) and $FF;
    t:= KeyData[i];
    j:= (j + t) and $FF;
    KeyData[i]:= KeyData[j];
    KeyData[j]:= t;
    t:= (t + KeyData[i]) and $FF;
    Pbytearray(@OutData)^[k]:= Pbytearray(@InData)^[k] xor KeyData[t];
  end;
end;


end.