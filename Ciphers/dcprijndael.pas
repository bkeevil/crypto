unit DCPrijndael;

{$MODE Delphi}

interface
uses
  Classes, Sysutils, Crypto;

const
  BC= 4;
  MAXROUNDS= 14;

type

  { TCipherRijndael }

  TCipherRijndael= class(TCipher)
  protected
    numrounds: longword;
    rk, drk: array[0..MAXROUNDS,0..7] of DWord;
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
{$I DCPrijndael.inc}

class function TCipherRijndael.MaxKeySize: integer;
begin
  Result:= 256;
end;

class function TCipherRijndael.Algorithm: TCipherAlgorithm;
begin
  Result:= caRijndael;
end;

class function TCipherRijndael.BlockSize: Integer;
begin
  Result := 128;
end;

class function TCipherRijndael.SelfTest: boolean;
const
  Key1: array[0..15] of byte=
    ($00,$01,$02,$03,$05,$06,$07,$08,$0A,$0B,$0C,$0D,$0F,$10,$11,$12);
  InData1: array[0..15] of byte=
    ($50,$68,$12,$A4,$5F,$08,$C8,$89,$B9,$7F,$59,$80,$03,$8B,$83,$59);
  OutData1: array[0..15] of byte=
    ($D8,$F5,$32,$53,$82,$89,$EF,$7D,$06,$B5,$06,$A4,$FD,$5B,$E9,$C9);
  Key2: array[0..23] of byte=
    ($A0,$A1,$A2,$A3,$A5,$A6,$A7,$A8,$AA,$AB,$AC,$AD,$AF,$B0,$B1,$B2,
     $B4,$B5,$B6,$B7,$B9,$BA,$BB,$BC);
  InData2: array[0..15] of byte=
    ($4F,$1C,$76,$9D,$1E,$5B,$05,$52,$C7,$EC,$A8,$4D,$EA,$26,$A5,$49);
  OutData2: array[0..15] of byte=
    ($F3,$84,$72,$10,$D5,$39,$1E,$23,$60,$60,$8E,$5A,$CB,$56,$05,$81);
  Key3: array[0..31] of byte=
    ($00,$01,$02,$03,$05,$06,$07,$08,$0A,$0B,$0C,$0D,$0F,$10,$11,$12,
     $14,$15,$16,$17,$19,$1A,$1B,$1C,$1E,$1F,$20,$21,$23,$24,$25,$26);
  InData3: array[0..15] of byte=
    ($5E,$25,$CA,$78,$F0,$DE,$55,$80,$25,$24,$D3,$8D,$A3,$FE,$44,$56);
  OutData3: array[0..15] of byte=
    ($E8,$B7,$2B,$4E,$8B,$E2,$43,$43,$8C,$9F,$FF,$1F,$0E,$20,$58,$72);
var
  Block: array[0..15] of byte;
  Cipher: TCipherRijndael;
begin
  FillChar(Block, SizeOf(Block), 0);
  Cipher:= TCipherRijndael.Create(@Key1,SizeOf(Key1) * 8);
  Cipher.EncryptBlock(InData1,Block);
  Result:= boolean(CompareMem(@Block,@OutData1,16));
  Cipher.DecryptBlock(Block,Block);
  Cipher.Free;
  Result:= Result and boolean(CompareMem(@Block,@InData1,16));
  Cipher := TCipherRijndael.Create(@Key2,Sizeof(Key2)*8);
  Cipher.EncryptBlock(InData2,Block);
  Result:= Result and boolean(CompareMem(@Block,@OutData2,16));
  Cipher.DecryptBlock(Block,Block);
  Cipher.Free;
  Result:= Result and boolean(CompareMem(@Block,@InData2,16));
  Cipher := TCipherRijndael.Create(@Key3,Sizeof(Key3)*8);
  Cipher.EncryptBlock(InData3,Block);
  Result:= Result and boolean(CompareMem(@Block,@OutData3,16));
  Cipher.DecryptBlock(Block,Block);
  Cipher.Free;
  Result:= Result and boolean(CompareMem(@Block,@InData3,16));
end;

procedure InvMixColumn(a: PByteArray; BC: byte);
var
  j: longword;
begin
  for j:= 0 to (BC-1) do
    PDWord(@(a^[j*4]))^:= PDWord(@U1[a^[j*4+0]])^ xor
                       PDWord(@U2[a^[j*4+1]])^ xor
                       PDWord(@U3[a^[j*4+2]])^ xor
                       PDWord(@U4[a^[j*4+3]])^;
end;

procedure TCipherRijndael.InitKey(const Key; Size: longword);
var
  KC, ROUNDS, j, r, t, rconpointer: longword;
  tk: array[0..MAXKC-1,0..3] of byte;
begin
  Size:= Size div 8;

  FillChar(tk,Sizeof(tk),0);
  Move(Key,tk,Size);
  if Size<= 16 then
  begin
    KC:= 4;
    Rounds:= 10;
  end
  else if Size<= 24 then
  begin
    KC:= 6;
    Rounds:= 12;
  end
  else
  begin
    KC:= 8;
    Rounds:= 14;
  end;
  numrounds:= rounds;
  r:= 0;
  t:= 0;
  j:= 0;
  while (j< KC) and (r< (rounds+1)) do
  begin
    while (j< KC) and (t< BC) do
    begin
      rk[r,t]:= PDWord(@tk[j])^;
      Inc(j);
      Inc(t);
    end;
    if t= BC then
    begin
      t:= 0;
      Inc(r);
    end;
  end;
  rconpointer:= 0;
  while (r< (rounds+1)) do
  begin
    tk[0,0]:= tk[0,0] xor S[tk[KC-1,1]];
    tk[0,1]:= tk[0,1] xor S[tk[KC-1,2]];
    tk[0,2]:= tk[0,2] xor S[tk[KC-1,3]];
    tk[0,3]:= tk[0,3] xor S[tk[KC-1,0]];
    tk[0,0]:= tk[0,0] xor rcon[rconpointer];
    Inc(rconpointer);
    if KC<> 8 then
    begin
      for j:= 1 to (KC-1) do
        PDWord(@tk[j])^:= PDWord(@tk[j])^ xor PDWord(@tk[j-1])^;
    end
    else
    begin
      for j:= 1 to ((KC div 2)-1) do
        PDWord(@tk[j])^:= PDWord(@tk[j])^ xor PDWord(@tk[j-1])^;
      tk[KC div 2,0]:= tk[KC div 2,0] xor S[tk[KC div 2 - 1,0]];
      tk[KC div 2,1]:= tk[KC div 2,1] xor S[tk[KC div 2 - 1,1]];
      tk[KC div 2,2]:= tk[KC div 2,2] xor S[tk[KC div 2 - 1,2]];
      tk[KC div 2,3]:= tk[KC div 2,3] xor S[tk[KC div 2 - 1,3]];
      for j:= ((KC div 2) + 1) to (KC-1) do
        PDWord(@tk[j])^:= PDWord(@tk[j])^ xor PDWord(@tk[j-1])^;
    end;
    j:= 0;
    while (j< KC) and (r< (rounds+1)) do
    begin
      while (j< KC) and (t< BC) do
      begin
        rk[r,t]:= PDWord(@tk[j])^;
        Inc(j);
        Inc(t);
      end;
      if t= BC then
      begin
        Inc(r);
        t:= 0;
      end;
    end;
  end;
  Move(rk,drk,Sizeof(rk));
  for r:= 1 to (numrounds-1) do
    InvMixColumn(@drk[r],BC);
end;

destructor TCipherRijndael.Destroy;
begin
  numrounds:= 0;
  FillChar(rk,Sizeof(rk),0);
  FillChar(drk,Sizeof(drk),0);
  inherited Destroy;
end;

procedure TCipherRijndael.EncryptBlock(const InData; var OutData);
var
  r: longword;
  tempb: array[0..MAXBC-1,0..3] of byte;
  a: array[0..MAXBC,0..3] of byte;
begin
  PDword(@a[0,0])^:= PDword(@InData)^;
  PDword(@a[1,0])^:= PDword(pointer(@InData)+4)^;
  PDword(@a[2,0])^:= PDword(pointer(@InData)+8)^;
  PDword(@a[3,0])^:= PDword(pointer(@InData)+12)^;
  for r:= 0 to (numrounds-2) do
  begin
    PDWord(@tempb[0])^:= PDWord(@a[0])^ xor rk[r,0];
    PDWord(@tempb[1])^:= PDWord(@a[1])^ xor rk[r,1];
    PDWord(@tempb[2])^:= PDWord(@a[2])^ xor rk[r,2];
    PDWord(@tempb[3])^:= PDWord(@a[3])^ xor rk[r,3];
    PDWord(@a[0])^:= PDWord(@T1[tempb[0,0]])^ xor
                     PDWord(@T2[tempb[1,1]])^ xor
                     PDWord(@T3[tempb[2,2]])^ xor
                     PDWord(@T4[tempb[3,3]])^;
    PDWord(@a[1])^:= PDWord(@T1[tempb[1,0]])^ xor
                     PDWord(@T2[tempb[2,1]])^ xor
                     PDWord(@T3[tempb[3,2]])^ xor
                     PDWord(@T4[tempb[0,3]])^;
    PDWord(@a[2])^:= PDWord(@T1[tempb[2,0]])^ xor
                     PDWord(@T2[tempb[3,1]])^ xor
                     PDWord(@T3[tempb[0,2]])^ xor
                     PDWord(@T4[tempb[1,3]])^;
    PDWord(@a[3])^:= PDWord(@T1[tempb[3,0]])^ xor
                     PDWord(@T2[tempb[0,1]])^ xor
                     PDWord(@T3[tempb[1,2]])^ xor
                     PDWord(@T4[tempb[2,3]])^;
  end;
  PDWord(@tempb[0])^:= PDWord(@a[0])^ xor rk[numrounds-1,0];
  PDWord(@tempb[1])^:= PDWord(@a[1])^ xor rk[numrounds-1,1];
  PDWord(@tempb[2])^:= PDWord(@a[2])^ xor rk[numrounds-1,2];
  PDWord(@tempb[3])^:= PDWord(@a[3])^ xor rk[numrounds-1,3];
  a[0,0]:= T1[tempb[0,0],1];
  a[0,1]:= T1[tempb[1,1],1];
  a[0,2]:= T1[tempb[2,2],1];
  a[0,3]:= T1[tempb[3,3],1];
  a[1,0]:= T1[tempb[1,0],1];
  a[1,1]:= T1[tempb[2,1],1];
  a[1,2]:= T1[tempb[3,2],1];
  a[1,3]:= T1[tempb[0,3],1];
  a[2,0]:= T1[tempb[2,0],1];
  a[2,1]:= T1[tempb[3,1],1];
  a[2,2]:= T1[tempb[0,2],1];
  a[2,3]:= T1[tempb[1,3],1];
  a[3,0]:= T1[tempb[3,0],1];
  a[3,1]:= T1[tempb[0,1],1];
  a[3,2]:= T1[tempb[1,2],1];
  a[3,3]:= T1[tempb[2,3],1];
  PDWord(@a[0])^:= PDWord(@a[0])^ xor rk[numrounds,0];
  PDWord(@a[1])^:= PDWord(@a[1])^ xor rk[numrounds,1];
  PDWord(@a[2])^:= PDWord(@a[2])^ xor rk[numrounds,2];
  PDWord(@a[3])^:= PDWord(@a[3])^ xor rk[numrounds,3];

  PDword(@OutData)^:= PDword(@a[0,0])^;
  PDword(pointer(@OutData)+4)^:= PDword(@a[1,0])^;
  PDword(pointer(@OutData)+8)^:= PDword(@a[2,0])^;
  PDword(pointer(@OutData)+12)^:= PDword(@a[3,0])^;
end;

procedure TCipherRijndael.DecryptBlock(const InData; var OutData);
var
  r: longword;
  tempb: array[0..MAXBC-1,0..3] of byte;
  a: array[0..MAXBC,0..3] of byte;
begin
  PDword(@a[0,0])^:= PDword(@InData)^;
  PDword(@a[1,0])^:= PDword(pointer(@InData)+4)^;
  PDword(@a[2,0])^:= PDword(pointer(@InData)+8)^;
  PDword(@a[3,0])^:= PDword(pointer(@InData)+12)^;
  for r:= NumRounds downto 2 do
  begin
    PDWord(@tempb[0])^:= PDWord(@a[0])^ xor drk[r,0];
    PDWord(@tempb[1])^:= PDWord(@a[1])^ xor drk[r,1];
    PDWord(@tempb[2])^:= PDWord(@a[2])^ xor drk[r,2];
    PDWord(@tempb[3])^:= PDWord(@a[3])^ xor drk[r,3];
    PDWord(@a[0])^:= PDWord(@T5[tempb[0,0]])^ xor
                     PDWord(@T6[tempb[3,1]])^ xor
                     PDWord(@T7[tempb[2,2]])^ xor
                     PDWord(@T8[tempb[1,3]])^;
    PDWord(@a[1])^:= PDWord(@T5[tempb[1,0]])^ xor
                     PDWord(@T6[tempb[0,1]])^ xor
                     PDWord(@T7[tempb[3,2]])^ xor
                     PDWord(@T8[tempb[2,3]])^;
    PDWord(@a[2])^:= PDWord(@T5[tempb[2,0]])^ xor
                     PDWord(@T6[tempb[1,1]])^ xor
                     PDWord(@T7[tempb[0,2]])^ xor
                     PDWord(@T8[tempb[3,3]])^;
    PDWord(@a[3])^:= PDWord(@T5[tempb[3,0]])^ xor
                     PDWord(@T6[tempb[2,1]])^ xor
                     PDWord(@T7[tempb[1,2]])^ xor
                     PDWord(@T8[tempb[0,3]])^;
  end;
  PDWord(@tempb[0])^:= PDWord(@a[0])^ xor drk[1,0];
  PDWord(@tempb[1])^:= PDWord(@a[1])^ xor drk[1,1];
  PDWord(@tempb[2])^:= PDWord(@a[2])^ xor drk[1,2];
  PDWord(@tempb[3])^:= PDWord(@a[3])^ xor drk[1,3];
  a[0,0]:= S5[tempb[0,0]];
  a[0,1]:= S5[tempb[3,1]];
  a[0,2]:= S5[tempb[2,2]];
  a[0,3]:= S5[tempb[1,3]];
  a[1,0]:= S5[tempb[1,0]];
  a[1,1]:= S5[tempb[0,1]];
  a[1,2]:= S5[tempb[3,2]];
  a[1,3]:= S5[tempb[2,3]];
  a[2,0]:= S5[tempb[2,0]];
  a[2,1]:= S5[tempb[1,1]];
  a[2,2]:= S5[tempb[0,2]];
  a[2,3]:= S5[tempb[3,3]];
  a[3,0]:= S5[tempb[3,0]];
  a[3,1]:= S5[tempb[2,1]];
  a[3,2]:= S5[tempb[1,2]];
  a[3,3]:= S5[tempb[0,3]];
  PDWord(@a[0])^:= PDWord(@a[0])^ xor drk[0,0];
  PDWord(@a[1])^:= PDWord(@a[1])^ xor drk[0,1];
  PDWord(@a[2])^:= PDWord(@a[2])^ xor drk[0,2];
  PDWord(@a[3])^:= PDWord(@a[3])^ xor drk[0,3];
  PDword(@OutData)^:= PDword(@a[0,0])^;
  PDword(pointer(@OutData)+4)^:= PDword(@a[1,0])^;
  PDword(pointer(@OutData)+8)^:= PDword(@a[2,0])^;
  PDword(pointer(@OutData)+12)^:= PDword(@a[3,0])^;
end;

end.