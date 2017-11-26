unit DCPblowfish;

{$MODE Delphi}

interface

uses
  Classes, Sysutils, Crypto;

type

  { TCipherBlowfish }

  TCipherBlowfish= class(TCipher)
    protected
      SBox: array[0..3,0..255] of DWord;
      PBox: array[0..17] of DWord;
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

{$I DCPblowfish.inc}

destructor TCipherBlowfish.Destroy;
begin
  FillChar(SBox,Sizeof(SBox),$FF);
  FillChar(PBox,Sizeof(PBox),$FF);
  inherited Destroy;
end;

class function TCipherBlowfish.Algorithm: TCipherAlgorithm;
begin
  Result:= caBlowfish;
end;

class function TCipherBlowfish.MaxKeySize: integer;
begin
  Result:= 448;
end;

class function TCipherBlowfish.BlockSize: Integer;
begin
  Result := 64;
end;

class function TCipherBlowfish.SelfTest: boolean;
const
  Key1: array[0..7] of byte= ($00,$00,$00,$00,$00,$00,$00,$00);
  Key2: array[0..7] of byte= ($7C,$A1,$10,$45,$4A,$1A,$6E,$57);
  InData1: array[0..7] of byte= ($00,$00,$00,$00,$00,$00,$00,$00);
  InData2: array[0..7] of byte= ($01,$A1,$D6,$D0,$39,$77,$67,$42);
  OutData1: array[0..7] of byte= ($4E,$F9,$97,$45,$61,$98,$DD,$78);
  OutData2: array[0..7] of byte= ($59,$C6,$82,$45,$EB,$05,$28,$2B);
var
  Cipher: TCipherBlowfish;
  Data: array[0..7] of byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Cipher:= TCipherBlowfish.Create(@Key1,SizeOf(Key1)*8);
  Cipher.EncryptBlock(InData1,Data);
  Result:= boolean(CompareMem(@Data,@OutData1,Sizeof(Data)));
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData1,Sizeof(Data))) and Result;
  Cipher.Destroy;
  Cipher := TCipherBlowfish.Create(@Key2,Sizeof(Key2)*8);
  Cipher.EncryptBlock(InData2,Data);
  Result:= boolean(CompareMem(@Data,@OutData2,Sizeof(Data))) and Result;
  Cipher.DecryptBlock(Data,Data);
  Result:= boolean(CompareMem(@Data,@InData2,Sizeof(Data))) and Result;
  Cipher.Free;
end;

procedure TCipherBlowfish.InitKey(const Key; Size: longword);
var
  i, k: longword;
  A: DWord;
  KeyB: PByteArray;
  Block: array[0..7] of byte;
begin
  FillChar(Block, SizeOf(Block), 0);
  Size:= Size div 8;
  KeyB:= @Key;
  Move(SBoxOrg,SBox,Sizeof(SBox));
  Move(PBoxOrg,PBox,Sizeof(PBox));
  k:= 0;
  for i:= 0 to 17 do
  begin
    A:= dword(KeyB^[(k+3) mod Size]);
    A:= A + (dword(KeyB^[(k+2) mod Size]) shl 8);
    A:= A + (dword(KeyB^[(k+1) mod Size]) shl 16);
    A:= A + (dword(KeyB^[k]) shl 24);
    PBox[i]:= PBox[i] xor A;
    k:= (k+4) mod Size;
  end;
  FillChar(Block,Sizeof(Block),0);
  for i:= 0 to 8 do
  begin
    EncryptBlock(Block,Block);
    PBox[i*2]:= dword(Block[3]) + (dword(Block[2]) shl 8) + (dword(Block[1]) shl 16) + (dword(Block[0]) shl 24);
    PBox[i*2+1]:= dword(Block[7]) + (dword(Block[6]) shl 8) + (dword(Block[5]) shl 16) + (dword(Block[4]) shl 24);
  end;
  for k:= 0 to 3 do
  begin
    for i:= 0 to 127 do
    begin
      EncryptBlock(Block,Block);
      SBox[k,i*2]:= dword(Block[3]) + (dword(Block[2]) shl 8) + (dword(Block[1]) shl 16) + (dword(Block[0]) shl 24);
      SBox[k,i*2+1]:= dword(Block[7]) + (dword(Block[6]) shl 8) + (dword(Block[5]) shl 16) + (dword(Block[4]) shl 24);
    end;
  end;
end;

procedure TCipherBlowfish.EncryptBlock(const InData; var OutData);
var
  xL, xR: DWord;
begin
  xL:= Pdword(@InData)^;
  xR:= Pdword(pointer(@InData)+4)^;
  xL:= ((xL and $FF) shl 24) or ((xL and $FF00) shl 8) or ((xL and $FF0000) shr 8) or ((xL and $FF000000) shr 24);
  xR:= ((xR and $FF) shl 24) or ((xR and $FF00) shl 8) or ((xR and $FF0000) shr 8) or ((xR and $FF000000) shr 24);
  xL:= xL xor PBox[0];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[1];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[2];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[3];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[4];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[5];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[6];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[7];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[8];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[9];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[10];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[11];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[12];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[13];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[14];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[15];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[16];
  xR:= xR xor PBox[17];
  xL:= ((xL and $FF) shl 24) or ((xL and $FF00) shl 8) or ((xL and $FF0000) shr 8) or ((xL and $FF000000) shr 24);
  xR:= ((xR and $FF) shl 24) or ((xR and $FF00) shl 8) or ((xR and $FF0000) shr 8) or ((xR and $FF000000) shr 24);
  Pdword(@OutData)^:= xR;
  Pdword(pointer(@OutData)+4)^:= xL;
end;

procedure TCipherBlowfish.DecryptBlock(const InData; var OutData);
var
  xL, xR: DWord;
begin
  xL:= Pdword(@InData)^;
  xR:= Pdword(pointer(@InData)+4)^;
  xL:= (xL shr 24) or ((xL shr 8) and $FF00) or ((xL shl 8) and $FF0000) or (xL shl 24);
  xR:= (xR shr 24) or ((xR shr 8) and $FF00) or ((xR shl 8) and $FF0000) or (xR shl 24);
  xL:= xL xor PBox[17];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[16];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[15];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[14];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[13];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[12];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[11];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[10];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[9];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[8];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[7];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[6];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[5];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[4];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[3];
  xR:= xR xor (((SBox[0,(xL shr 24) and $FF] + SBox[1,(xL shr 16) and $FF]) xor
    SBox[2,(xL shr 8) and $FF]) + SBox[3,xL and $FF]) xor PBox[2];
  xL:= xL xor (((SBox[0,(xR shr 24) and $FF] + SBox[1,(xR shr 16) and $FF]) xor
    SBox[2,(xR shr 8) and $FF]) + SBox[3,xR and $FF]) xor PBox[1];
  xR:= xR xor PBox[0];
  xL:= (xL shr 24) or ((xL shr 8) and $FF00) or ((xL shl 8) and $FF0000) or (xL shl 24);
  xR:= (xR shr 24) or ((xR shr 8) and $FF00) or ((xR shl 8) and $FF0000) or (xR shl 24);
  Pdword(@OutData)^:= xR;
  Pdword(pointer(@OutData)+4)^:= xL;
end;

end.