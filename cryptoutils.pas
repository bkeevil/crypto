unit CryptoUtils;

{$mode delphi}{$H+}

interface

uses
  Classes, SysUtils;

type
  TBlock64 = array[0..1] of DWORD;
  TBlock128 = array[0..3] of DWORD;
  TBlock256 = array[0..7] of DWORD;
  PBlock64 = ^TBlock64;
  PBlock128 = ^TBlock128;
  PBlock256 = ^TBlock256;

  TKey128 = TBlock128;
  TKey256 = TBlock256;
  PKey128 = ^TKey128;
  PKey256 = ^TKey256;

procedure XORMem(A,B,R: Pointer; Size: Integer);
procedure XOR64(A,B,R: Pointer);
procedure XOR128(A,B,R: Pointer);

procedure Inc64(V: Pointer);
procedure Inc128(V: Pointer);

function CompareMem(A,B: Pointer; Size: Integer): Integer;
function BufferToHex(Buffer: Pointer; Size: Integer): String;
function LFSR(var N: Cardinal): Cardinal;
function ROTL32(var X: Cardinal; Y: Byte = 1): Cardinal;
function ROTR32(var X: Cardinal; Y: Byte = 1): Cardinal;
function XpowYmodN(X, Y, N: Cardinal): Cardinal;
function GeneratePrime: Cardinal;
function MillerRabin(N: Cardinal; Trials: Byte): Boolean;

implementation

uses
  Rand;

procedure XORMem(A,B,R: Pointer; Size: Integer);
var
  PA,PB,PR: PByte;
  X: Word;
begin
  for X := 0 to Size - 1 do
    begin
      PA := PByte(PtrInt(A)+X);
      PB := PByte(PtrInt(B)+X);
      PR := PByte(PtrInt(R)+X);
      PR^ := PA^ xor PB^;
    end;
end;

procedure XOR64(A,B,R: Pointer);
begin
  PBlock64(R)[0] := PBlock64(A)[0] xor PBlock64(B)[0];
  PBlock64(R)[1] := PBlock64(A)[1] xor PBlock64(B)[1];
end;

procedure XOR128(A,B,R: Pointer);
begin
  PBlock128(R)[0] := PBlock128(A)[0] xor PBlock128(B)[0];
  PBlock128(R)[1] := PBlock128(A)[1] xor PBlock128(B)[1];
  PBlock128(R)[2] := PBlock128(A)[2] xor PBlock128(B)[2];
  PBlock128(R)[3] := PBlock128(A)[3] xor PBlock128(B)[3];
end;

procedure Inc64(V: Pointer);
begin
  inc(PBlock64(V)[1]);
  if PBlock64(V)[1] = 0 then
    inc(PBlock64(V)[0]);
end;

procedure Inc128(V: Pointer);
var
  i: integer;
begin
  Inc(PBlock128(V)[3]);
  i:= 3;
  while (i> 0) and (PBlock128(V)[i] = 0) do
    begin
      Inc(PBlock128(V)[i-1]);
      Dec(i);
    end;
end;

function CompareMem(A, B: Pointer; Size: Integer): Integer;
var
  X: Integer;
  PA, PB: PByte;
begin
  Result := 0;
  for X := 0 to Size - 1 do
    begin
      PA := PByte(PtrUInt(A) + X);
      PB := PByte(PtrUInt(B) + X);
      if PA^ > PB^ then
        begin
          Result := 1;
          Exit;
        end
      else
        if PB^ > PA^ then
          begin
            Result := -1;
            Exit;
          end;
    end;
end;

function BufferToHex(Buffer: Pointer; Size: Integer): String;
var               { Fails on large strings }
  X: Integer;
  B: Byte;
  S: String;
begin
  Result := '';
  for X := 0 to Size - 1 do
    begin
      B := PByte(PtrUInt(Buffer) + X)^;
      S := IntToHex(B,2)+' ';
      Result := Result + S;
    end;
end;

// Linear Feedback Shift Register
function LFSR(var N: Cardinal): Cardinal;
begin
  if (N and 1) > 0 then
    N := ((N xor $80000055) shr 1) or $80000000
  else
    N := N shr 1;
  Result := N;
end;

function ROTL32(var X: Cardinal; Y: Byte = 1): Cardinal;
begin
  X := (X shl Y) or (X shr (32-Y));
end;

function ROTR32(var X: Cardinal; Y: Byte = 1): Cardinal;
begin
  X := (X shr Y) or (x shl (32 -Y));
end;

// Raises X to the power Y in modulus N
function XpowYmodN(X, Y, N: Cardinal): Cardinal;
var
  A,B: QWORD;
begin
  A := 1; B := X;
  while Y > 0 do
    begin
      if Y mod 2 = 1 then
        A := (A * B) mod N;
      B := (B * B) mod N;
      Y := Y div 2;
    end;
  Result := A mod N;
end;

// Performs the Miller-Rabin primality test on N
function MillerRabin(N: Cardinal; Trials: Byte): Boolean;
var
  I: Byte;
  A: Cardinal;
begin
  Result := False;
  for I := 1 to Trials do
    begin
      A := (RNG.Generate mod (N-3)) + 2;  // Get random value between 2 and N-1
      if XpowYmodN(A,N-1,N) <> 1 then Exit;    // Is it prime?
    end;
  Result := True;
end;

// Generate a random 32 bit prime number
function GeneratePrime: Cardinal;
begin
  Result := RNG.Generate;
  if (Result and 1) = 0 then inc(Result);
  while not MillerRabin(Result,5) do inc(Result,2);
end;

end.
