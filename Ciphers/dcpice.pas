unit DCPice;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, Crypto;

type
  TCustomICE= class(TCipher)
  protected
    rounds: dword;
    ik_keysched: array[0..31,0..2] of dword;
    function f(p, sk: dword): dword;
    procedure key_sched_build(kb: pwordarray; n: dword; keyrot: pdwordarray);
    procedure InitIce(const Key; Size: longword; n: dword);
  public
    constructor Create(Key: Pointer; KeySize: Integer); override;
    destructor Destroy; override;
    procedure EncryptBlock(const InData; var OutData); override;
    procedure DecryptBlock(const InData; var OutData); override;
  end;

  { TCipherICE }

  TCipherICE= class(TCustomICE)
    protected
      procedure InitKey(const Key; Size: longword); override;
    public
      class function Algorithm: TCipherAlgorithm; override;
      class function BlockSize: Integer; override;
      class function MaxKeySize: integer; override;
      class function SelfTest: boolean; override;
  end;

  { TCipherThinICE }

  TCipherThinICE= class(TCustomICE)
    protected
      procedure InitKey(const Key; Size: longword); override;
    public
      class function Algorithm: TCipherAlgorithm; override;
      class function BlockSize: Integer; override;
      class function MaxKeySize: integer; override;
      class function SelfTest: boolean; override;
  end;

  { TCipherICE2 }

  TCipherICE2= class(TCustomICE)
    protected
      procedure InitKey(const Key; Size: longword); override;
    public
      class function Algorithm: TCipherAlgorithm; override;
      class function BlockSize: Integer; override;
      class function MaxKeySize: integer; override;
      class function SelfTest: boolean; override;
  end;

implementation
{$R-}{$Q-}

var
  ice_sbox: array[0..3,0..1023] of dword;
  ice_sboxdone: boolean;

const
  ice_smod: array[0..3,0..3] of dword= (
    (333, 313, 505, 369),
    (379, 375, 319, 391),
    (361, 445, 451, 397),
    (397, 425, 395, 505));
  ice_sxor: array[0..3,0..3] of dword= (
    ($83, $85, $9b, $cd),
    ($cc, $a7, $ad, $41),
    ($4b, $2e, $d4, $33),
    ($ea, $cb, $2e, $04));
  ice_keyrot: array[0..15] of dword= (
     0, 1, 2, 3, 2, 1, 3, 0,
     1, 3, 2, 0, 3, 1, 0, 2);
  ice_pbox: array[0..31] of dword= (
     $00000001,  $00000080,  $00000400,  $00002000,
     $00080000,  $00200000,  $01000000,  $40000000,
     $00000008,  $00000020,  $00000100,  $00004000,
     $00010000,  $00800000,  $04000000,  $20000000,
     $00000004,  $00000010,  $00000200,  $00008000,
     $00020000,  $00400000,  $08000000,  $10000000,
     $00000002,  $00000040,  $00000800,  $00001000,
     $00040000,  $00100000,  $02000000,  $80000000);

function SwapDword(a: dword): dword;
begin
  Result:= ((a and $FF) shl 24) or ((a and $FF00) shl 8) or ((a and $FF0000) shr 8) or ((a and $FF000000) shr 24);
end;

{******************************************************************************}

function gf_mult(a, b, m: dword): dword;
var
  res: dword;
begin
  res:= 0;
  while b<> 0 do
  begin
    if (b and 1)<> 0 then
      res:= res xor a;
    a:= a shl 1;
    b:= b shr 1;
    if a>= 256 then
      a:= a xor m;
  end;
  Result:= res;
end;

function gf_exp7(b, m: dword): dword;
var
  x: dword;
begin
  if b= 0 then
    Result:= 0
  else
  begin
    x:= gf_mult(b,b,m);
    x:= gf_mult(b,x,m);
    x:= gf_mult(x,x,m);
    Result:= gf_mult(b,x,m);
  end;
end;

function ice_perm32(x: dword): dword;
var
  res: dword;
  pbox: pdword;
begin
  res:= 0;
  pbox:= @ice_pbox;
  while x<> 0 do
  begin
    if (x and 1)<> 0 then
      res:= res or pbox^;
    Inc(pbox);
    x:= x shr 1;
  end;
  Result:= res;
end;

procedure ice_sboxes_init;
var
  i, col, row: dword;
  x: dword;
begin
  for i:= 0 to 1023 do
  begin
    col:= (i shr 1) and $FF;
    row:= (i and 1) or ((i and $200) shr 8);
    x:= gf_exp7(col xor ice_sxor[0,row],ice_smod[0,row]) shl 24;
    ice_sbox[0,i]:= ice_perm32(x);
    x:= gf_exp7(col xor ice_sxor[1,row],ice_smod[1,row]) shl 16;
    ice_sbox[1,i]:= ice_perm32(x);
    x:= gf_exp7(col xor ice_sxor[2,row],ice_smod[2,row]) shl  8;
    ice_sbox[2,i]:= ice_perm32(x);
    x:= gf_exp7(col xor ice_sxor[3,row],ice_smod[3,row]);
    ice_sbox[3,i]:= ice_perm32(x);
  end;
end;

function TCustomICE.f(p, sk: dword): dword;
var
  tl, tr, al, ar: dword;
begin
  tl:= ((p shr 16) and $3ff) or (((p shr 14) or (p shl 18)) and $ffc00);
  tr:= (p and $3ff) or ((p shl 2) and $ffc00);
  al:= ik_keysched[sk,2] and (tl xor tr);
  ar:= al xor tr;
  al:= al xor tl;
  al:= al xor ik_keysched[sk,0];
  ar:= ar xor ik_keysched[sk,1];
  Result:= ice_sbox[0,al shr 10] or ice_sbox[1,al and $3ff] or
           ice_sbox[2,ar shr 10] or ice_sbox[3,ar and $3ff];
end;


procedure TCustomICE.key_sched_build(kb: pwordarray; n: dword; keyrot: pdwordarray);
var
  i, j, k, kr: dword;
  keys: pdwordarray;
  currentsk: pdword;
  currentkb: pword;
  bit: dword;
begin
  for i:= 0 to 7 do
  begin
    kr:= keyrot^[i];
    keys:= @ik_keysched[n+i];
    for j:= 0 to 2 do
      keys^[j]:= 0;
    for j:= 0 to 14 do
    begin
      currentsk:= @keys^[j mod 3];
      for k:= 0 to 3 do
      begin
        currentkb:= @kb^[(kr + k) and 3];
        bit:= currentkb^ and 1;
        currentsk^:= (currentsk^ shl 1) or bit;
        currentkb^:= (currentkb^ shr 1) or ((bit xor 1) shl 15);
      end;
    end;
  end;
end;

procedure TCustomICE.InitIce(const Key; Size: longword; n: dword);
var
  i, j: dword;
  kb: array[0..3] of word;
  keyb: array[0..15] of byte;
begin
  FillChar(keyb,Sizeof(keyb),0);
  Move(key,keyb,Size div 8);
  if n> 0 then
    rounds:= 16 * n
  else
    rounds:= 8;

  if rounds= 8 then
  begin
    for i:= 0 to 4 do
      kb[3 - i]:= (keyb[i*2] shl 8) or keyb[i*2 + 1];
    key_sched_build(@kb,0,@ice_keyrot);
  end
  else
  begin
    for i:= 0 to (n-1) do
    begin
      for j:= 0 to 3 do
        kb[3-j]:= (keyb[i*8 + j*2] shl 8) or keyb[i*8 + j*2 + 1];
      key_sched_build(@kb,i*8,@ice_keyrot);
      key_sched_build(@kb,rounds - 8 - i*8,@ice_keyrot[8]);
    end;
  end;
end;

constructor TCustomICE.Create(Key: Pointer; KeySize: Integer);
begin
  inherited Create(Key,KeySize);
  if not ice_sboxdone then
  begin
    ice_sboxes_init;
    ice_sboxdone:= true;
  end;
end;

destructor TCustomIce.Destroy;
begin
  FillChar(ik_keysched,Sizeof(ik_keysched),0);
  Rounds:= 0;
  inherited Destroy;
end;

procedure TCustomICE.EncryptBlock(const InData; var OutData);
var
  i, l, r: dword;
begin
  l:= SwapDWord(Pdword(@InData)^);
  r:= SwapDWord(Pdword(pointer(@InData)+4)^);
  i:= 0;
  while i< rounds do
  begin
    l:= l xor f(r,i);
    r:= r xor f(l,i+1);
    Inc(i,2);
  end;
  Pdword(@OutData)^:= SwapDWord(r);
  Pdword(pointer(@OutData)+4)^:= SwapDWord(l);
end;

procedure TCustomICE.DecryptBlock(const InData; var OutData);
var
  l, r: dword;
  i: integer;
begin
  l:= SwapDWord(Pdword(@InData)^);
  r:= SwapDWord(Pdword(pointer(@InData)+4)^);
  i:= rounds-1;
  while i> 0 do
  begin
    l:= l xor f(r,i);
    r:= r xor f(l,i-1);
    Dec(i,2);
  end;
  Pdword(@OutData)^:= SwapDWord(r);
  Pdword(pointer(@OutData)+4)^:= SwapDWord(l);
end;


{ TCipherICE }

class function TCipherICE.MaxKeySize: integer;
begin
  Result:= 64;
end;

class function TCipherICE.Algorithm: TCipherAlgorithm;
begin
  Result:= caICE;
end;

class function TCipherICE.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherICE.SelfTest: boolean;
const
  Key1: array[0..7] of byte= ($de,$ad,$be,$ef,$01,$23,$45,$67);
  InData1: array[0..7] of byte= ($fe,$dc,$ba,$98,$76,$54,$32,$10);
  OutData1: array[0..7] of byte= ($7d,$6e,$f1,$ef,$30,$d4,$7a,$96);
var
  Cipher: TCipherICE;
  Data: array[0..7] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherICE.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InData1,Data);
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData1,Sizeof(Data))) and Result;
  Cipher.Free;
end;

procedure TCipherICE.InitKey(const Key; Size: longword);
begin
  InitIce(Key,Size,1);
end;

{ TCipherThinICE }

class function TCipherThinICE.MaxKeySize: integer;
begin
  Result:= 64;
end;

class function TCipherThinICE.Algorithm: TCipherAlgorithm;
begin
  Result:= caThinICE;
end;

class function TCipherThinICE.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherThinICE.SelfTest: boolean;
const
  Key1: array[0..7] of byte= ($de,$ad,$be,$ef,$01,$23,$45,$67);
  InData1: array[0..7] of byte= ($fe,$dc,$ba,$98,$76,$54,$32,$10);
  OutData1: array[0..7] of byte= ($de,$24,$0d,$83,$a0,$0a,$9c,$c0);
var
  Cipher: TCipherThinICE;
  Data: array[0..7] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherThinICE.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InData1,Data);
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData1,Sizeof(Data))) and Result;
  Cipher.Free;
end;

procedure TCipherThinICE.InitKey(const Key; Size: longword);
begin
  InitIce(Key,Size,0);
end;

{ TCipherICE2 }

class function TCipherICE2.MaxKeySize: integer;
begin
  Result:= 128;
end;

class function TCipherICE2.Algorithm: TCipherAlgorithm;
begin
  Result:= caICE2;
end;

class function TCipherICE2.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherICE2.SelfTest: boolean;
const
  Key1: array[0..15] of byte=
    ($00,$11,$22,$33,$44,$55,$66,$77,$88,$99,$aa,$bb,$cc,$dd,$ee,$ff);
  InData1: array[0..7] of byte= ($fe,$dc,$ba,$98,$76,$54,$32,$10);
  OutData1: array[0..7] of byte= ($f9,$48,$40,$d8,$69,$72,$f2,$1c);
var
  Cipher: TCipherICE2;
  Data: array[0..7] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherICE2.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InData1,Data);
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData1,Sizeof(Data))) and Result;
  Cipher.Free;
end;

procedure TCipherICE2.InitKey(const Key; Size: longword);
begin
  InitIce(Key,Size,2);
end;


initialization
  ice_sboxdone:= false;
end.