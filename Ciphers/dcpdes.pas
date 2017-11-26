unit DCPdes;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, Crypto;

type
  TCustomDES= class(TCipher)
    protected
      procedure DoInit(KeyB: PByteArray; KeyData: PDWordArray);
      procedure EncryptDES(const InData; var OutData; KeyData: PDWordArray);
      procedure DecryptDES(const InData; var OutData; KeyData: PDWordArray);
  end;

type

  { TCipherDES }

  TCipherDES= class(TCustomDES)
    protected
      KeyData: array[0..31] of dword;
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

  { TCipher3DES }

  TCipher3DES= class(TCustomDES)
    protected
      KeyData: array[0..2,0..31] of dword;
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

{$I DCPdes.inc}

procedure hperm_op(var a, t: dword; n, m: dword);
begin
  t:= ((a shl (16 - n)) xor a) and m;
  a:= a xor t xor (t shr (16 - n));
end;

procedure perm_op(var a, b, t: dword; n, m: dword);
begin
  t:= ((a shr n) xor b) and m;
  b:= b xor t;
  a:= a xor (t shl n);
end;

procedure TCustomDES.DoInit(KeyB: PByteArray; KeyData: PDwordArray);
var
  c, d, t, s, t2, i: dword;
begin
  t := 0;
  c:= KeyB^[0] or (KeyB^[1] shl 8) or (KeyB^[2] shl 16) or (KeyB^[3] shl 24);
  d:= KeyB^[4] or (KeyB^[5] shl 8) or (KeyB^[6] shl 16) or (KeyB^[7] shl 24);
  perm_op(d,c,t,4,$0f0f0f0f);
  hperm_op(c,t,dword(-2),$cccc0000);
  hperm_op(d,t,dword(-2),$cccc0000);
  perm_op(d,c,t,1,$55555555);
  perm_op(c,d,t,8,$00ff00ff);
  perm_op(d,c,t,1,$55555555);
  d:= ((d and $ff) shl 16) or (d and $ff00) or ((d and $ff0000) shr 16) or
        ((c and $f0000000) shr 4);
  c:= c and $fffffff;
  for i:= 0 to 15 do
  begin
    if shifts2[i]<> 0 then
    begin
      c:= ((c shr 2) or (c shl 26));
      d:= ((d shr 2) or (d shl 26));
    end
    else
    begin
      c:= ((c shr 1) or (c shl 27));
      d:= ((d shr 1) or (d shl 27));
    end;
    c:= c and $fffffff;
    d:= d and $fffffff;
    s:= des_skb[0,c and $3f] or
        des_skb[1,((c shr  6) and $03) or ((c shr  7) and $3c)] or
        des_skb[2,((c shr 13) and $0f) or ((c shr 14) and $30)] or
        des_skb[3,((c shr 20) and $01) or ((c shr 21) and $06) or ((c shr 22) and $38)];
    t:= des_skb[4,d and $3f] or
        des_skb[5,((d shr  7) and $03) or ((d shr  8) and $3c)] or
        des_skb[6, (d shr 15) and $3f                         ] or
        des_skb[7,((d shr 21) and $0f) or ((d shr 22) and $30)];
    t2:= ((t shl 16) or (s and $ffff));
    KeyData^[(i shl 1)]:= ((t2 shl 2) or (t2 shr 30));
    t2:= ((s shr 16) or (t and $ffff0000));
    KeyData^[(i shl 1)+1]:= ((t2 shl 6) or (t2 shr 26));
  end;
end;

procedure TCustomDES.EncryptDES(const InData; var OutData; KeyData: PDWordArray);
var
  l, r, t, u: dword;
  i: longint;
begin
  r:= PDword(@InData)^;
  l:= PDword(pointer(@InData)+4)^;
  t:= ((l shr 4) xor r) and $0f0f0f0f;
  r:= r xor t;
  l:= l xor (t shl 4);
  t:= ((r shr 16) xor l) and $0000ffff;
  l:= l xor t;
  r:= r xor (t shl 16);
  t:= ((l shr 2) xor r) and $33333333;
  r:= r xor t;
  l:= l xor (t shl 2);
  t:= ((r shr 8) xor l) and $00ff00ff;
  l:= l xor t;
  r:= r xor (t shl 8);
  t:= ((l shr 1) xor r) and $55555555;
  r:= r xor t;
  l:= l xor (t shl 1);
  r:= (r shr 29) or (r shl 3);
  l:= (l shr 29) or (l shl 3);
  i:= 0;
  while i< 32 do
  begin
    u:= r xor KeyData^[i  ];
    t:= r xor KeyData^[i+1];
    t:= (t shr 4) or (t shl 28);
    l:= l xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    u:= l xor KeyData^[i+2];
    t:= l xor KeyData^[i+3];
    t:= (t shr 4) or (t shl 28);
    r:= r xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    u:= r xor KeyData^[i+4];
    t:= r xor KeyData^[i+5];
    t:= (t shr 4) or (t shl 28);
    l:= l xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    u:= l xor KeyData^[i+6];
    t:= l xor KeyData^[i+7];
    t:= (t shr 4) or (t shl 28);
    r:= r xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    Inc(i,8);
  end;
  r:= (r shr 3) or (r shl 29);
  l:= (l shr 3) or (l shl 29);
  t:= ((r shr 1) xor l) and $55555555;
  l:= l xor t;
  r:= r xor (t shl 1);
  t:= ((l shr 8) xor r) and $00ff00ff;
  r:= r xor t;
  l:= l xor (t shl 8);
  t:= ((r shr 2) xor l) and $33333333;
  l:= l xor t;
  r:= r xor (t shl 2);
  t:= ((l shr 16) xor r) and $0000ffff;
  r:= r xor t;
  l:= l xor (t shl 16);
  t:= ((r shr 4) xor l) and $0f0f0f0f;
  l:= l xor t;
  r:= r xor (t shl 4);
  PDword(@OutData)^:= l;
  PDword(pointer(@OutData)+4)^:= r;
end;

procedure TCustomDES.DecryptDES(const InData; var OutData; KeyData: PDWordArray);
var
  l, r, t, u: dword;
  i: longint;
begin
  r:= PDword(@InData)^;
  l:= PDword(pointer(@InData)+4)^;
  t:= ((l shr 4) xor r) and $0f0f0f0f;
  r:= r xor t;
  l:= l xor (t shl 4);
  t:= ((r shr 16) xor l) and $0000ffff;
  l:= l xor t;
  r:= r xor (t shl 16);
  t:= ((l shr 2) xor r) and $33333333;
  r:= r xor t;
  l:= l xor (t shl 2);
  t:= ((r shr 8) xor l) and $00ff00ff;
  l:= l xor t;
  r:= r xor (t shl 8);
  t:= ((l shr 1) xor r) and $55555555;
  r:= r xor t;
  l:= l xor (t shl 1);
  r:= (r shr 29) or (r shl 3);
  l:= (l shr 29) or (l shl 3);
  i:= 30;
  while i> 0 do
  begin
    u:= r xor KeyData^[i  ];
    t:= r xor KeyData^[i+1];
    t:= (t shr 4) or (t shl 28);
    l:= l xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    u:= l xor KeyData^[i-2];
    t:= l xor KeyData^[i-1];
    t:= (t shr 4) or (t shl 28);
    r:= r xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    u:= r xor KeyData^[i-4];
    t:= r xor KeyData^[i-3];
    t:= (t shr 4) or (t shl 28);
    l:= l xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    u:= l xor KeyData^[i-6];
    t:= l xor KeyData^[i-5];
    t:= (t shr 4) or (t shl 28);
    r:= r xor des_SPtrans[0,(u shr  2) and $3f] xor
              des_SPtrans[2,(u shr 10) and $3f] xor
              des_SPtrans[4,(u shr 18) and $3f] xor
              des_SPtrans[6,(u shr 26) and $3f] xor
              des_SPtrans[1,(t shr  2) and $3f] xor
              des_SPtrans[3,(t shr 10) and $3f] xor
              des_SPtrans[5,(t shr 18) and $3f] xor
              des_SPtrans[7,(t shr 26) and $3f];
    Dec(i,8);
  end;
  r:= (r shr 3) or (r shl 29);
  l:= (l shr 3) or (l shl 29);
  t:= ((r shr 1) xor l) and $55555555;
  l:= l xor t;
  r:= r xor (t shl 1);
  t:= ((l shr 8) xor r) and $00ff00ff;
  r:= r xor t;
  l:= l xor (t shl 8);
  t:= ((r shr 2) xor l) and $33333333;
  l:= l xor t;
  r:= r xor (t shl 2);
  t:= ((l shr 16) xor r) and $0000ffff;
  r:= r xor t;
  l:= l xor (t shl 16);
  t:= ((r shr 4) xor l) and $0f0f0f0f;
  l:= l xor t;
  r:= r xor (t shl 4);
  PDword(@OutData)^:= l;
  PDword(pointer(@OutData)+4)^:= r;
end;

class function TCipherDES.MaxKeySize: integer;
begin
  Result:= 64;
end;

class function TCipherDES.Algorithm: TCipherAlgorithm;
begin
  //Result:= caDES;
end;

class function TCipherDES.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherDES.SelfTest: boolean;
const
  InData1: array[0..7] of byte=
    ($07,$56,$D8,$E0,$77,$47,$61,$D2);
  OutData1: array[0..7] of byte=
    ($0C,$D3,$DA,$02,$00,$21,$DC,$09);
  Key1: array[0..7] of byte=
    ($01,$70,$F1,$75,$46,$8F,$B5,$E6);
  InData2: array[0..7] of byte=
    ($48,$0D,$39,$00,$6E,$E7,$62,$F2);
  OutData2: array[0..7] of byte=
    ($A1,$F9,$91,$55,$41,$02,$0B,$56);
  Key2: array[0..7] of byte=
    ($02,$58,$16,$16,$46,$29,$B0,$07);
var
  Cipher: TCipherDES;
  Data: array[0..7] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherDES.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InData1,Data);
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= Result and boolean(CompareMem(@Data,@InData1,Sizeof(Data)));
  Cipher.Free;
  Cipher := TCipherDES.Create(@Key2,SizeOf(Key2) * 8);
  Cipher.EncryptBlock(InData2,Data);
  Result:= Result and boolean(CompareMem(@Data,@OutData2,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= Result and boolean(CompareMem(@Data,@InData2,Sizeof(Data)));
  Cipher.Free;
end;

procedure TCipherDES.InitKey(const Key; Size: longword);
var
  KeyB: array[0..7] of byte;
begin
  FillChar(KeyB,Sizeof(KeyB),0);
  Move(Key,KeyB,Size div 8);
  DoInit(@KeyB,@KeyData);
end;

destructor TCipherDES.Destroy;
begin
  FillChar(KeyData,SizeOf(KeyData),0);
  inherited Destroy;
end;


procedure TCipherDES.EncryptBlock(const InData; var OutData);
begin
  EncryptDES(InData,OutData,@KeyData);
end;

procedure TCipherDES.DecryptBlock(const InData; var OutData);
begin
  DecryptDES(InData,OutData,@KeyData);
end;

{ TCipher3DES }

class function TCipher3DES.MaxKeySize: integer;
begin
  Result:= 192;
end;

class function TCipher3DES.Algorithm: TCipherAlgorithm;
begin
  Result:= ca3DES;
end;

class function TCipher3DES.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipher3DES.SelfTest: boolean;
const
  Key: array[0..23] of byte=
    ($01,$23,$45,$67,$89,$ab,$cd,$ef,$fe,$dc,$ba,$98,
     $76,$54,$32,$10,$89,$ab,$cd,$ef,$01,$23,$45,$67);
  PlainText: array[0..7] of byte=
    ($01,$23,$45,$67,$89,$ab,$cd,$e7);
  CipherText: array[0..7] of byte=
    ($de,$0b,$7c,$06,$ae,$5e,$0e,$d5);
var
  Cipher: TCipher3DES;
  Block: array[0..7] of byte;
begin
  FillChar(Block, SizeOf(Block), 0);
  Cipher:= TCipher3DES.Create(@Key,SizeOf(Key)*8);
  Cipher.EncryptBlock(PlainText,Block);
  Result:= CompareMem(@Block,@CipherText,Sizeof(CipherText));
  Cipher.DecryptBlock(Block,Block);
  Result:= Result and CompareMem(@Block,@PlainText,Sizeof(PlainText));
  Cipher.Free;
end;

procedure TCipher3DES.InitKey(const Key; Size: longword);
var
  KeyB: array[0..2,0..7] of byte;
begin
  FillChar(KeyB,Sizeof(KeyB),0);
  Move(Key,KeyB,Size div 8);
  DoInit(@KeyB[0],@KeyData[0]);
  DoInit(@KeyB[1],@KeyData[1]);
  if Size> 128 then
    DoInit(@KeyB[2],@KeyData[2])
  else
    Move(KeyData[0],KeyData[2],128);
end;

destructor TCipher3DES.Destroy;
begin
  FillChar(KeyData,Sizeof(KeyData),0);
  inherited Destroy;
end;

procedure TCipher3DES.EncryptBlock(const InData; var OutData);
begin
  EncryptDES(InData,OutData,@KeyData[0]);
  DecryptDES(OutData,OutData,@KeyData[1]);
  EncryptDES(OutData,OutData,@KeyData[2]);
end;

procedure TCipher3DES.DecryptBlock(const InData; var OutData);
begin
  DecryptDES(InData,OutData,@KeyData[2]);
  EncryptDES(OutData,OutData,@KeyData[1]);
  DecryptDES(OutData,OutData,@KeyData[0]);
end;

end.