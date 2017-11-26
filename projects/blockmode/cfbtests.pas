unit cfbtests;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testutils, testregistry,
  Crypto;

type

  { TCFBTests }

  TCFBTests = class(TTestCase)
  private

  protected
    FKey: array[1..32] of Byte;
    FIV: array[1..16] of Byte;
    FCipher: TCipher;
    FEnc: TCipherCFBMode;
    FDec: TCipherCFBMode;
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure OneFullBlock;
    procedure TwoFullBlocks;
    procedure EncHalfFullHalf;
    procedure DecHalfFullHalf;
    procedure EncDecByByte;
    procedure LargeEncDec;
  end;

implementation

procedure TCFBTests.OneFullBlock;
var
  D: array[1..16] of Byte;
  X: Integer;
begin
  for X := 1 to 16 do
    D[X] := X;
  FEnc.Encrypt(@D,16);
  FDec.Decrypt(@D,16);
  for X := 1 to 16 do
    Self.AssertEquals(X,D[X]);
end;

procedure TCFBTests.TwoFullBlocks;
var
  D: array[1..16] of Byte;
  X: Integer;
begin
  for X := 1 to 16 do
    D[X] := X;
  FEnc.Encrypt(@D,16);
  FDec.Decrypt(@D,16);
  for X := 1 to 16 do
    Self.AssertEquals(X,D[X]);
  FEnc.Encrypt(@D,16);
  FDec.Decrypt(@D,16);
  for X := 1 to 16 do
    Self.AssertEquals(X,D[X]);
end;

procedure TCFBTests.EncHalfFullHalf;
var
  D,E: array[1..32] of Byte;
  X: Integer;
begin
  for X := 1 to 32 do
    D[X] := X;
  E := D;
  FEnc.Encrypt(@D,8);
  FEnc.Encrypt(@D[9],16);
  FEnc.Encrypt(@D[25],8);
  FDec.Decrypt(@D,32);
  for X := 1 to 32 do
    Self.AssertEquals(X,D[X]);
end;

procedure TCFBTests.DecHalfFullHalf;
var
  D,E: array[1..32] of Byte;
  X: Integer;
begin
  for X := 1 to 32 do
    D[X] := X;
  E := D;
  FEnc.Encrypt(@D,32);
  FDec.Decrypt(@D,8);
  FDec.Decrypt(@D[9],16);
  FDec.Decrypt(@D[25],8);
  for X := 1 to 32 do
    Self.AssertEquals(X,D[X]);
end;

procedure TCFBTests.EncDecByByte;
var
  D,E: array[1..255] of Byte;
  X: Integer;
begin
  for X := 1 to 255 do
    D[X] := X;

  for X := 1 to 255 do
    FEnc.Encrypt(@D[X],1);
  for X := 1 to 255 do
    FDec.Decrypt(@D[X],1);
  for X := 1 to 255 do
    Self.AssertEquals(X,D[X]);

  for X := 1 to 255 do
    FEnc.Encrypt(@D[X],1);
  for X := 1 to 255 do
    FDec.Decrypt(@D[X],1);
  for X := 1 to 255 do
    Self.AssertEquals(X,D[X]);
end;

procedure TCFBTests.LargeEncDec;
var
  D,E: array[1..255] of Byte;
  X: Integer;
begin
  for X := 1 to 255 do
    D[X] := X;

  FEnc.Encrypt(@D,255);
  for X := 1 to 255 do
    FDec.Decrypt(@D[X],1);
  for X := 1 to 255 do
    Self.AssertEquals(X,D[X]);

  for X := 1 to 255 do
    FEnc.Encrypt(@D[X],1);
  FDec.Decrypt(@D,255);
  for X := 1 to 255 do
    Self.AssertEquals(X,D[X]);
end;

procedure TCFBTests.SetUp;
begin
  FillChar(FKey,32,1);
  FillChar(FIV,16,0);
  FCipher := CreateCipher(caTwofish,@FKey,256);
  FEnc := TCipherCFBMode.Create(FCipher,@FIV);
  FDec := TCipherCFBMode.Create(FCipher,@FIV);
end;

procedure TCFBTests.TearDown;
begin
  FEnc.Free;
  FDec.Free;
  FCipher.Free;
end;

initialization

  RegisterTest(TCFBTests);
end.

