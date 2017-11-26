unit DCPcast256;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, Crypto;

type
  TCipherCAST256= class(TCipher)
  protected
    Kr, Km: array[0..11,0..3] of DWord;
    procedure InitKey(const Key; Size: longword); override;
  public
    destructor Destroy; override;
    class function Algorithm: TCipherAlgorithm; override;
    class function MaxKeySize: integer; override;
    class function SelfTest: boolean; override;
    class function BlockSize: Integer; override;
    procedure EncryptBlock(const InData; var OutData); override;
    procedure DecryptBlock(const InData; var OutData); override;
  end;

implementation

{$R-}{$Q-}
{$I DCPcast256.inc}

function LRot32(a, n: dword): dword;
begin
  Result:= (a shl n) or (a shr (32-n));
end;

function SwapDword(a: dword): dword;
begin
  Result:= ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

function F1(a,rk,mk: DWord): DWord;
var
  t: DWord;
begin
  t:= LRot32(mk + a,rk);
  Result:= ((S1[t shr 24] xor S2[(t shr 16) and $FF]) - S3[(t shr 8) and $FF]) + S4[t and $FF];
end;
function F2(a,rk,mk: DWord): DWord;
var
  t: DWord;
begin
  t:= LRot32(mk xor a,rk);
  Result:= ((S1[t shr 24] - S2[(t shr 16) and $FF]) + S3[(t shr 8) and $FF]) xor S4[t and $FF];
end;
function F3(a,rk,mk: DWord): DWord;
var
  t: DWord;
begin
  t:= LRot32(mk - a,rk);
  Result:= ((S1[t shr 24] + S2[(t shr 16) and $FF]) xor S3[(t shr 8) and $FF]) - S4[t and $FF];
end;

destructor TCipherCAST256.Destroy;
begin
  FillChar(Kr,Sizeof(Kr),$FF);
  FillChar(Km,Sizeof(Km),$FF);
  inherited Destroy;
end;

class function TCipherCAST256.MaxKeySize: integer;
begin
  Result:= 256;
end;

class function TCipherCAST256.BlockSize: Integer;
begin
  Result := 128;
end;

class function TCipherCAST256.Algorithm: TCipherAlgorithm;
begin
  Result:= caCast256;
end;

class function TCipherCAST256.SelfTest: boolean;
const
  Key1: array[0..15] of byte=
    ($23,$42,$bb,$9e,$fa,$38,$54,$2c,$0a,$f7,$56,$47,$f2,$9f,$61,$5d);
  InBlock1: array[0..15] of byte=
    ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$0c,$9b,$28,$07);
  OutBlock1: array[0..15] of byte=
    ($96,$3a,$8a,$50,$ce,$b5,$4d,$08,$e0,$de,$e0,$f1,$d0,$41,$3d,$cf);
  Key2: array[0..23] of byte=
    ($23,$42,$bb,$9e,$fa,$38,$54,$2c,$be,$d0,$ac,$83,$94,$0a,$c2,$98,$ba,$c7,$7a,$77,$17,$94,$28,$63);
  InBlock2: array[0..15] of byte=
    ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$de,$25,$5a,$ff);
  OutBlock2: array[0..15] of byte=
    ($2b,$c1,$92,$9f,$30,$13,$47,$a9,$9d,$3f,$3e,$45,$ad,$34,$01,$e8);
  Key3: array[0..31] of byte=
    ($23,$42,$bb,$9e,$fa,$38,$54,$2c,$be,$d0,$ac,$83,$94,$0a,$c2,$98,$8d,$7c,$47,$ce,$26,$49,$08,$46,$1c,$c1,$b5,$13,$7a,$e6,$b6,$04);
  InBlock3: array[0..15] of byte=
    ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$c5,$fc,$eb,$19);
  OutBlock3: array[0..15] of byte=
    ($1e,$2e,$bc,$6c,$9f,$2e,$43,$8e,$1d,$90,$d9,$b9,$c6,$85,$32,$86);
var
  Block: array[0..15] of byte;
  Cipher: TCipherCAST256;
begin
  FillChar(Block, SizeOf(Block), 0);
  Cipher:= TCipherCAST256.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InBlock1,Block);
  Result:= boolean(CompareMem(@Block,@OutBlock1,8));
  Cipher.DecryptBlock(Block,Block);
  Result:= Result and boolean(CompareMem(@Block,@InBlock1,16));
  Cipher.Free;
  Cipher := TCipherCAST256.Create(@Key2,SizeOf(Key2) * 8);
  Cipher.EncryptBlock(InBlock2,Block);
  Result:= Result and boolean(CompareMem(@Block,@OutBlock2,8));
  Cipher.DecryptBlock(Block,Block);
  Result:= Result and boolean(CompareMem(@Block,@InBlock2,16));
  Cipher.Free;
  Cipher := TCipherCAST256.Create(@Key3,Sizeof(Key3)*8);
  Cipher.EncryptBlock(InBlock3,Block);
  Result:= Result and boolean(CompareMem(@Block,@OutBlock3,8));
  Cipher.DecryptBlock(Block,Block);
  Result:= Result and boolean(CompareMem(@Block,@InBlock3,16));
  Cipher.Free;
end;

procedure TCipherCAST256.InitKey(const Key; Size: longword);
var
  x: array[0..7] of DWord;
  cm, cr: DWord;
  i, j: longword;
  tr, tm: array[0..7] of DWord;
begin
  Size:= Size div 8;

  FillChar(x,Sizeof(x),0);
  Move(Key,x,Size);

  cm:= $5a827999;
  cr:= 19;
  for i:= 0 to 7 do
    x[i]:= (x[i] shl 24) or ((x[i] shl 8) and $FF0000) or ((x[i] shr 8) and $FF00) or (x[i] shr 24);
  for i:= 0 to 11 do
  begin
    for j:= 0 to 7 do
    begin
      tm[j]:= cm;
      Inc(cm,$6ed9eba1);
      tr[j]:= cr;
      Inc(cr,17);
    end;
    x[6]:= x[6] xor f1(x[7],tr[0],tm[0]);
    x[5]:= x[5] xor f2(x[6],tr[1],tm[1]);
    x[4]:= x[4] xor f3(x[5],tr[2],tm[2]);
    x[3]:= x[3] xor f1(x[4],tr[3],tm[3]);
    x[2]:= x[2] xor f2(x[3],tr[4],tm[4]);
    x[1]:= x[1] xor f3(x[2],tr[5],tm[5]);
    x[0]:= x[0] xor f1(x[1],tr[6],tm[6]);
    x[7]:= x[7] xor f2(x[0],tr[7],tm[7]);

    for j:= 0 to 7 do
    begin
      tm[j]:= cm;
      Inc(cm,$6ed9eba1);
      tr[j]:= cr;
      Inc(cr,17);
    end;
    x[6]:= x[6] xor f1(x[7],tr[0],tm[0]);
    x[5]:= x[5] xor f2(x[6],tr[1],tm[1]);
    x[4]:= x[4] xor f3(x[5],tr[2],tm[2]);
    x[3]:= x[3] xor f1(x[4],tr[3],tm[3]);
    x[2]:= x[2] xor f2(x[3],tr[4],tm[4]);
    x[1]:= x[1] xor f3(x[2],tr[5],tm[5]);
    x[0]:= x[0] xor f1(x[1],tr[6],tm[6]);
    x[7]:= x[7] xor f2(x[0],tr[7],tm[7]);

    Kr[i,0]:= x[0] and 31;
    Kr[i,1]:= x[2] and 31;
    Kr[i,2]:= x[4] and 31;
    Kr[i,3]:= x[6] and 31;
    Km[i,0]:= x[7];
    Km[i,1]:= x[5];
    Km[i,2]:= x[3];
    Km[i,3]:= x[1];
  end;
  FillChar(x,Sizeof(x),$FF);
end;

procedure TCipherCAST256.EncryptBlock(const InData; var OutData);
var
  A: array[0..3] of DWord;
begin
  A[0]:= PDWord(@InData)^;
  A[1]:= PDWord(pointer(@InData)+4)^;
  A[2]:= PDWord(pointer(@InData)+8)^;
  A[3]:= PDWord(pointer(@InData)+12)^;

  A[0]:= SwapDWord(A[0]);
  A[1]:= SwapDWord(A[1]);
  A[2]:= SwapDWord(A[2]);
  A[3]:= SwapDWord(A[3]);
  A[2]:= A[2] xor f1(A[3],kr[0,0],km[0,0]);
  A[1]:= A[1] xor f2(A[2],kr[0,1],km[0,1]);
  A[0]:= A[0] xor f3(A[1],kr[0,2],km[0,2]);
  A[3]:= A[3] xor f1(A[0],kr[0,3],km[0,3]);
  A[2]:= A[2] xor f1(A[3],kr[1,0],km[1,0]);
  A[1]:= A[1] xor f2(A[2],kr[1,1],km[1,1]);
  A[0]:= A[0] xor f3(A[1],kr[1,2],km[1,2]);
  A[3]:= A[3] xor f1(A[0],kr[1,3],km[1,3]);
  A[2]:= A[2] xor f1(A[3],kr[2,0],km[2,0]);
  A[1]:= A[1] xor f2(A[2],kr[2,1],km[2,1]);
  A[0]:= A[0] xor f3(A[1],kr[2,2],km[2,2]);
  A[3]:= A[3] xor f1(A[0],kr[2,3],km[2,3]);
  A[2]:= A[2] xor f1(A[3],kr[3,0],km[3,0]);
  A[1]:= A[1] xor f2(A[2],kr[3,1],km[3,1]);
  A[0]:= A[0] xor f3(A[1],kr[3,2],km[3,2]);
  A[3]:= A[3] xor f1(A[0],kr[3,3],km[3,3]);
  A[2]:= A[2] xor f1(A[3],kr[4,0],km[4,0]);
  A[1]:= A[1] xor f2(A[2],kr[4,1],km[4,1]);
  A[0]:= A[0] xor f3(A[1],kr[4,2],km[4,2]);
  A[3]:= A[3] xor f1(A[0],kr[4,3],km[4,3]);
  A[2]:= A[2] xor f1(A[3],kr[5,0],km[5,0]);
  A[1]:= A[1] xor f2(A[2],kr[5,1],km[5,1]);
  A[0]:= A[0] xor f3(A[1],kr[5,2],km[5,2]);
  A[3]:= A[3] xor f1(A[0],kr[5,3],km[5,3]);

  A[3]:= A[3] xor f1(A[0],kr[6,3],km[6,3]);
  A[0]:= A[0] xor f3(A[1],kr[6,2],km[6,2]);
  A[1]:= A[1] xor f2(A[2],kr[6,1],km[6,1]);
  A[2]:= A[2] xor f1(A[3],kr[6,0],km[6,0]);
  A[3]:= A[3] xor f1(A[0],kr[7,3],km[7,3]);
  A[0]:= A[0] xor f3(A[1],kr[7,2],km[7,2]);
  A[1]:= A[1] xor f2(A[2],kr[7,1],km[7,1]);
  A[2]:= A[2] xor f1(A[3],kr[7,0],km[7,0]);
  A[3]:= A[3] xor f1(A[0],kr[8,3],km[8,3]);
  A[0]:= A[0] xor f3(A[1],kr[8,2],km[8,2]);
  A[1]:= A[1] xor f2(A[2],kr[8,1],km[8,1]);
  A[2]:= A[2] xor f1(A[3],kr[8,0],km[8,0]);
  A[3]:= A[3] xor f1(A[0],kr[9,3],km[9,3]);
  A[0]:= A[0] xor f3(A[1],kr[9,2],km[9,2]);
  A[1]:= A[1] xor f2(A[2],kr[9,1],km[9,1]);
  A[2]:= A[2] xor f1(A[3],kr[9,0],km[9,0]);
  A[3]:= A[3] xor f1(A[0],kr[10,3],km[10,3]);
  A[0]:= A[0] xor f3(A[1],kr[10,2],km[10,2]);
  A[1]:= A[1] xor f2(A[2],kr[10,1],km[10,1]);
  A[2]:= A[2] xor f1(A[3],kr[10,0],km[10,0]);
  A[3]:= A[3] xor f1(A[0],kr[11,3],km[11,3]);
  A[0]:= A[0] xor f3(A[1],kr[11,2],km[11,2]);
  A[1]:= A[1] xor f2(A[2],kr[11,1],km[11,1]);
  A[2]:= A[2] xor f1(A[3],kr[11,0],km[11,0]);
  A[0]:= SwapDWord(A[0]);
  A[1]:= SwapDWord(A[1]);
  A[2]:= SwapDWord(A[2]);
  A[3]:= SwapDWord(A[3]);

  PDWord(@OutData)^:= A[0];
  PDWord(pointer(@OutData)+4)^:= A[1];
  PDWord(pointer(@OutData)+8)^:= A[2];
  PDWord(pointer(@OutData)+12)^:= A[3];
end;

procedure TCipherCAST256.DecryptBlock(const InData; var OutData);
var
  A: array[0..3] of DWord;
begin
  A[0]:= PDWord(@InData)^;
  A[1]:= PDWord(pointer(@InData)+4)^;
  A[2]:= PDWord(pointer(@InData)+8)^;
  A[3]:= PDWord(pointer(@InData)+12)^;

  A[0]:= SwapDWord(A[0]);
  A[1]:= SwapDWord(A[1]);
  A[2]:= SwapDWord(A[2]);
  A[3]:= SwapDWord(A[3]);
  A[2]:= A[2] xor f1(A[3],kr[11,0],km[11,0]);
  A[1]:= A[1] xor f2(A[2],kr[11,1],km[11,1]);
  A[0]:= A[0] xor f3(A[1],kr[11,2],km[11,2]);
  A[3]:= A[3] xor f1(A[0],kr[11,3],km[11,3]);
  A[2]:= A[2] xor f1(A[3],kr[10,0],km[10,0]);
  A[1]:= A[1] xor f2(A[2],kr[10,1],km[10,1]);
  A[0]:= A[0] xor f3(A[1],kr[10,2],km[10,2]);
  A[3]:= A[3] xor f1(A[0],kr[10,3],km[10,3]);
  A[2]:= A[2] xor f1(A[3],kr[9,0],km[9,0]);
  A[1]:= A[1] xor f2(A[2],kr[9,1],km[9,1]);
  A[0]:= A[0] xor f3(A[1],kr[9,2],km[9,2]);
  A[3]:= A[3] xor f1(A[0],kr[9,3],km[9,3]);
  A[2]:= A[2] xor f1(A[3],kr[8,0],km[8,0]);
  A[1]:= A[1] xor f2(A[2],kr[8,1],km[8,1]);
  A[0]:= A[0] xor f3(A[1],kr[8,2],km[8,2]);
  A[3]:= A[3] xor f1(A[0],kr[8,3],km[8,3]);
  A[2]:= A[2] xor f1(A[3],kr[7,0],km[7,0]);
  A[1]:= A[1] xor f2(A[2],kr[7,1],km[7,1]);
  A[0]:= A[0] xor f3(A[1],kr[7,2],km[7,2]);
  A[3]:= A[3] xor f1(A[0],kr[7,3],km[7,3]);
  A[2]:= A[2] xor f1(A[3],kr[6,0],km[6,0]);
  A[1]:= A[1] xor f2(A[2],kr[6,1],km[6,1]);
  A[0]:= A[0] xor f3(A[1],kr[6,2],km[6,2]);
  A[3]:= A[3] xor f1(A[0],kr[6,3],km[6,3]);

  A[3]:= A[3] xor f1(A[0],kr[5,3],km[5,3]);
  A[0]:= A[0] xor f3(A[1],kr[5,2],km[5,2]);
  A[1]:= A[1] xor f2(A[2],kr[5,1],km[5,1]);
  A[2]:= A[2] xor f1(A[3],kr[5,0],km[5,0]);
  A[3]:= A[3] xor f1(A[0],kr[4,3],km[4,3]);
  A[0]:= A[0] xor f3(A[1],kr[4,2],km[4,2]);
  A[1]:= A[1] xor f2(A[2],kr[4,1],km[4,1]);
  A[2]:= A[2] xor f1(A[3],kr[4,0],km[4,0]);
  A[3]:= A[3] xor f1(A[0],kr[3,3],km[3,3]);
  A[0]:= A[0] xor f3(A[1],kr[3,2],km[3,2]);
  A[1]:= A[1] xor f2(A[2],kr[3,1],km[3,1]);
  A[2]:= A[2] xor f1(A[3],kr[3,0],km[3,0]);
  A[3]:= A[3] xor f1(A[0],kr[2,3],km[2,3]);
  A[0]:= A[0] xor f3(A[1],kr[2,2],km[2,2]);
  A[1]:= A[1] xor f2(A[2],kr[2,1],km[2,1]);
  A[2]:= A[2] xor f1(A[3],kr[2,0],km[2,0]);
  A[3]:= A[3] xor f1(A[0],kr[1,3],km[1,3]);
  A[0]:= A[0] xor f3(A[1],kr[1,2],km[1,2]);
  A[1]:= A[1] xor f2(A[2],kr[1,1],km[1,1]);
  A[2]:= A[2] xor f1(A[3],kr[1,0],km[1,0]);
  A[3]:= A[3] xor f1(A[0],kr[0,3],km[0,3]);
  A[0]:= A[0] xor f3(A[1],kr[0,2],km[0,2]);
  A[1]:= A[1] xor f2(A[2],kr[0,1],km[0,1]);
  A[2]:= A[2] xor f1(A[3],kr[0,0],km[0,0]);
  A[0]:= SwapDWord(A[0]);
  A[1]:= SwapDWord(A[1]);
  A[2]:= SwapDWord(A[2]);
  A[3]:= SwapDWord(A[3]);

  PDWord(@OutData)^:= A[0];
  PDWord(pointer(@OutData)+4)^:= A[1];
  PDWord(pointer(@OutData)+8)^:= A[2];
  PDWord(pointer(@OutData)+12)^:= A[3];
end;

end.