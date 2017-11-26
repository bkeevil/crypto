unit DCPrc2;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, Crypto;

type

  { TCipherRC2 }

  TCipherRC2= class(TCipher)
    protected
      KeyData: array[0..63] of word;
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

{$I DCPrc2.inc}

function LRot16(a, n: word): word;
begin
  Result:= (a shl n) or (a shr (16-n));
end;

function RRot16(a, n: word): word;
begin
  Result:= (a shr n) or (a shl (16-n));
end;

destructor TCipherRC2.Destroy;
begin
  FillChar(KeyData,Sizeof(KeyData),0);
  inherited Destroy;
end;

class function TCipherRC2.MaxKeySize: integer;
begin
  Result:= 1024;
end;

class function TCipherRC2.Algorithm: TCipherAlgorithm;
begin
  Result:= caRC2;
end;

class function TCipherRC2.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherRC2.SelfTest: boolean;
const
  Key1: array[0..15] of byte=
    ($00,$01,$02,$03,$04,$05,$06,$07,$08,$09,$0A,$0B,$0C,$0D,$0E,$0F);
  InData1: array[0..7] of byte=
    ($00,$00,$00,$00,$00,$00,$00,$00);
  OutData1: array[0..7] of byte=
    ($50,$DC,$01,$62,$BD,$75,$7F,$31);
  Key2: array[0..15] of byte=
    ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01);
  InData2: array[0..7] of byte=
    ($00,$00,$00,$00,$00,$00,$00,$00);
  OutData2: array[0..7] of byte=
    ($21,$82,$9C,$78,$A9,$F9,$C0,$74);
var
  Cipher: TCipherRC2;
  Data: array[0..7] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherRC2.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InData1,Data);
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData1,Sizeof(Data))) and Result;
  Cipher.Free;

  Cipher := TCipherRC2.Create(@Key2,Sizeof(Key2)*8);
  Cipher.EncryptBlock(InData2,Data);
  Result:= boolean(CompareMem(@Data,@OutData2,Sizeof(Data))) and Result;
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData2,Sizeof(Data))) and Result;
  Cipher.Free;
end;

procedure TCipherRC2.InitKey(const Key; Size: longword);
var
  i: longword;
  KeyB: array[0..127] of byte;
begin
  FillChar(KeyB, SizeOf(KeyB), 0);
  Move(Key,KeyB,Size div 8);
  for i:= (Size div 8) to 127 do
    KeyB[i]:= sBox[(KeyB[i-(Size div 8)]+KeyB[i-1]) and $FF];
  KeyB[0]:= sBox[KeyB[0]];
  Move(KeyB,KeyData,Sizeof(KeyData));
end;

procedure TCipherRC2.EncryptBlock(const InData; var OutData);
var
  i, j: longword;
  w: array[0..3] of word;
begin
  Pdword(@w[0])^:= Pdword(@InData)^;
  Pdword(@w[2])^:= Pdword(pointer(@InData)+4)^;
  for i:= 0 to 15 do
  begin
    j:= i*4;
    w[0]:= LRot16((w[0]+(w[1] and (not w[3]))+(w[2] and w[3])+KeyData[j+0]),1);
    w[1]:= LRot16((w[1]+(w[2] and (not w[0]))+(w[3] and w[0])+KeyData[j+1]),2);
    w[2]:= LRot16((w[2]+(w[3] and (not w[1]))+(w[0] and w[1])+KeyData[j+2]),3);
    w[3]:= LRot16((w[3]+(w[0] and (not w[2]))+(w[1] and w[2])+KeyData[j+3]),5);
    if (i= 4) or (i= 10) then
    begin
      w[0]:= w[0]+KeyData[w[3] and 63];
      w[1]:= w[1]+KeyData[w[0] and 63];
      w[2]:= w[2]+KeyData[w[1] and 63];
      w[3]:= w[3]+KeyData[w[2] and 63];
    end;
  end;
  Pdword(@OutData)^:= Pdword(@w[0])^;
  Pdword(pointer(@OutData)+4)^:= Pdword(@w[2])^;
end;

procedure TCipherRC2.DecryptBlock(const InData; var OutData);
var
  i, j: longword;
  w: array[0..3] of word;
begin
  Pdword(@w[0])^:= Pdword(@InData)^;
  Pdword(@w[2])^:= Pdword(pointer(@InData)+4)^;
  for i:= 15 downto 0 do
  begin
    j:= i*4;
    w[3]:= RRot16(w[3],5)-(w[0] and (not w[2]))-(w[1] and w[2])-KeyData[j+3];
    w[2]:= RRot16(w[2],3)-(w[3] and (not w[1]))-(w[0] and w[1])-KeyData[j+2];
    w[1]:= RRot16(w[1],2)-(w[2] and (not w[0]))-(w[3] and w[0])-KeyData[j+1];
    w[0]:= RRot16(w[0],1)-(w[1] and (not w[3]))-(w[2] and w[3])-KeyData[j+0];
    if (i= 5) or (i= 11) then
    begin
      w[3]:= w[3]-KeyData[w[2] and 63];
      w[2]:= w[2]-KeyData[w[1] and 63];
      w[1]:= w[1]-KeyData[w[0] and 63];
      w[0]:= w[0]-KeyData[w[3] and 63];
    end;
  end;
  Pdword(@OutData)^:= Pdword(@w[0])^;
  Pdword(pointer(@OutData)+4)^:= Pdword(@w[2])^;
end;

end. 