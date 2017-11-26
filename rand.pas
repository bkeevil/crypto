unit Rand;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  { TEntropyAccumulator }

  TEntropyAccumulator = class(TObject)
    private
      FArray: array[1..8] of Integer;
      FMaxBits: Integer;
      FStream: TMemoryStream;
      FCounter: Byte;
      FAccumulator: Cardinal;
      FQuality: Double;
      FOnEntropy: TNotifyEvent;
      function GetData: Pointer;
      function GetNumBits: Integer;
      function GetSize: Integer;
      procedure UpdateStats(DW: Cardinal);
    public
      constructor Create;
      destructor Destroy;
      //
      procedure Reset;
      procedure MouseMove(X,Y: Integer);
      function Read: Cardinal;
      property Data: Pointer read GetData;
      property Size: Integer read GetSize;
      property NumBits: Integer read GetNumBits;
      property Quality: Double read FQuality;
      property MaxBits: Integer read FMaxBits write FMaxBits;
      property OnEntropy: TNotifyEvent read FOnEntropy write FOnEntropy;
  end;

  { TLinearFeedbackShiftRegister }

  TLinearFeedbackShiftRegister = class(TObject)
    private
      FSeed: Cardinal;
      FCurrent: Cardinal;
      procedure SetSeed(AValue: Cardinal);
    public
      constructor Create(ASeed: Cardinal = 0);
      function Next: Cardinal;
      procedure Reset;
      property Seed: Cardinal read FSeed write SetSeed;
  end;

  { TRandomNumberGenerator }

  TRandomNumberGenerator = class(TObject)
    private
      FLFSR: TLinearFeedbackShiftRegister;
      FEntropy: TEntropyAccumulator;
    public
      constructor Create;
      destructor Destroy; override;
      function Generate: Cardinal;
      //
      property Entropy: TEntropyAccumulator read FEntropy write FEntropy;
  end;

var
  RNG: TRandomNumberGenerator;

procedure FillRandom(Data: Pointer; Size: Integer);

implementation

uses
  DateUtils, CryptoUtils;

procedure FillRandom(Data: Pointer; Size: Integer);
var
  X: Integer;
  R: Cardinal;
begin
  for X := 1 to Size div 4 do
    begin
      R := RNG.Generate;
      System.Move(R,Pointer(PtrUInt(Data)+((X-1) * SizeOf(R)))^,SizeOf(R));
    end;
  X := Size mod 4;
  if X > 0 then
    begin
      R := RNG.Generate;
      System.Move(R,Pointer(PtrUInt(Data)+((Size div 4) * SizeOf(R)))^,X);
    end;
end;

{ TLinearFeedbackShiftRegister }

constructor TLinearFeedbackShiftRegister.Create(ASeed: Cardinal = 0);
begin
  if ASeed = 0 then
    Seed := Random($FFFFFFFE) + 1
  else
    Seed := ASeed;
end;

procedure TLinearFeedbackShiftRegister.SetSeed(AValue: Cardinal);
begin
  if AValue = 0 then
    AValue := $FFFFFFFF;
  FSeed := AValue;
  FCurrent := AValue;
end;

function TLinearFeedbackShiftRegister.Next: Cardinal;
begin
  Result := LFSR(FCurrent);
  if FCurrent = 0 then
    FCurrent := $FFFFFFFF;
end;

procedure TLinearFeedbackShiftRegister.Reset;
begin
  FCurrent := FSeed;
end;

{ TRandomNumberGenerator }

constructor TRandomNumberGenerator.Create;
begin
  FLFSR := TLinearFeedbackShiftRegister.Create;
end;

destructor TRandomNumberGenerator.Destroy;
begin
  FLFSR.Free;
  inherited Destroy;
end;

function TRandomNumberGenerator.Generate: Cardinal;
begin
  Result := FLFSR.Next xor Random($FFFFFFFF);
  if (FEntropy <> nil) and (FEntropy.Size > SizeOf(Cardinal)) then
    Result := FEntropy.Read xor Result;
end;

{ TEntropyAccumulator }

constructor TEntropyAccumulator.Create;
begin
  FStream := TMemoryStream.Create;
  FMaxBits := 2048;
  FAccumulator := Random($FFFFFFFF);
end;

destructor TEntropyAccumulator.Destroy;
begin
  FStream.Destroy;
end;

procedure TEntropyAccumulator.Reset;
var
  X: Integer;
begin
  FStream.Size := 0;
  FQuality := 0;
  FCounter := 0;
  for X := 1 to 8 do
    FArray[X] := 0;
end;

function TEntropyAccumulator.GetData: Pointer;
begin
  Result := FStream.Memory;
end;

function TEntropyAccumulator.GetNumBits: Integer;
begin
  Result := FStream.Size * 8;
end;

function TEntropyAccumulator.GetSize: Integer;
begin
  Result := FStream.Size;
end;

procedure TEntropyAccumulator.UpdateStats(DW: Cardinal);
var
  D: array[1..4] of Integer;
  Q: Double;
  X: Integer;
  B: Byte;
begin
  D[1] := DW and $FF;
  D[2] := (DW and $FF00) shr 8;
  D[3] := (DW and $FF0000) shr 16;
  D[4] := (DW and $FF000000) shr 24;

  // inc/dec bit array
  for X := 1 to 4 do
    begin
      B := D[X];
      if B and $80 > 0 then inc(FArray[1]) else dec(FArray[1]);
      if B and $40 > 0 then inc(FArray[2]) else dec(FArray[2]);
      if B and $20 > 0 then inc(FArray[3]) else dec(FArray[3]);
      if B and $10 > 0 then inc(FArray[4]) else dec(FArray[4]);
      if B and $8 > 0 then inc(FArray[5]) else dec(FArray[5]);
      if B and $4 > 0 then inc(FArray[6]) else dec(FArray[6]);
      if B and $2 > 0 then inc(FArray[7]) else dec(FArray[7]);
      if B and $1 > 0 then inc(FArray[8]) else dec(FArray[8]);
    end;

  // Calculate a quality score
  Q := 0;
  for X := 1 to 8 do
    Q := Q + (1-(Abs(FArray[X])/FStream.Size))*100;
  FQuality := Q / 8;
end;

procedure TEntropyAccumulator.MouseMove(X, Y: Integer);
var
  B,S: Byte;
  Q: Cardinal = 0;
begin
  if FStream.Size < (FMaxBits div 8) then
    begin
      if FCounter mod 2 = 1 then
        B := ((X mod 16) shl 4) + (y mod 16)
      else
        B := ((Y mod 16) shl 4) + (X mod 16);
      S := (FCounter mod 4) * 8;
      Q := B shl S;
      FAccumulator := LFSR(FAccumulator) xor Q;
      inc(FCounter);
      if FCounter mod 16 = 0 then
        begin
          FStream.Write(FAccumulator,SizeOf(Cardinal));
          UpdateStats(FAccumulator);
        end;
      if FCounter = 128 then FCounter := 0;
      if Assigned(FOnEntropy) and (FStream.Size >= (FMaxBits div 8)) then
        FOnEntropy(Self);
    end;
end;

function TEntropyAccumulator.Read: Cardinal;
begin
  if FStream.Size > SizeOf(Cardinal) then
    begin
      FStream.Position := FStream.Size - SizeOf(Cardinal);
      FStream.Read(Result,SizeOf(Result));
      FStream.Size := FStream.Size - SizeOf(Cardinal);
    end
  else
    Result := Random($FFFFFFFF);
end;

initialization
  Randomize;
  RNG := TRandomNumberGenerator.Create;
finalization
  RNG.Free;
end.

