unit DiffieHellman;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, CryptoUtils;

type
  TDiffieHellmanRequest = record
    Generator : DWORD;
    Modulus   : DWORD;
    Interim   : DWORD;
  end;

  TDiffieHellmanResponse = record
    Interim   : DWORD;
  end;

  { TDiffieHellman }

  TDiffieHellman = class(TObject)
    private
      FModulus   : DWORD;
      FGenerator : DWORD;
      FPrivateA  : DWORD;
      FPrivateB  : DWORD;
      FInterimA  : DWORD;
      FInterimB  : DWORD;
      FKey       : DWORD;
      //
      procedure Clean;
      procedure CreateKeys(out Generator, Modulus: DWORD);
      function CreateSenderInterKey: DWORD;
      function CreateRecipientInterKey(Generator, Modulus: DWORD): DWORD;
      procedure CreateSenderEncryptionKey(RecipientInterKey: DWORD);
      procedure CreateRecipientEncryptionKey(SenderInterKey: DWORD);
    public
      constructor Create;
      destructor Destroy; override;
      //
      procedure Clear;
      function GenerateRequest: TDiffieHellmanRequest;
      function ProcessRequest(Request: TDiffieHellmanRequest): TDiffieHellmanResponse;
      procedure ReceiveResponse(Response: TDiffieHellmanResponse);
      //
      property Key: DWORD read FKey;
  end;

  TDiffieHellman128Request = array[0..3] of TDiffieHellmanRequest;
  PDiffieHellman128Request = ^TDiffieHellman128Request;
  TDiffieHellman128Response = array[0..3] of TDiffieHellmanResponse;
  PDiffieHellman128Response = ^TDiffieHellman128Response;

  { TDiffieHellman128 }

  TDiffieHellman128 = class(TObject)
    private
      A: array[0..3] of TDiffieHellman;
      function GetKey: TKey128;
    public
      constructor Create;
      destructor Destroy; override;
      procedure Clear;
      function GenerateRequest: TDiffieHellman128Request;
      function ProcessRequest(Request: TDiffieHellman128Request): TDiffieHellman128Response;
      procedure ReceiveResponse(Response: TDiffieHellman128Response);
      function KeysMatch(DH: TDiffieHellman128): Boolean;
      property Key: TKey128 read GetKey;
  end;

  TDiffieHellman256Request = array[0..7] of TDiffieHellmanRequest;
  PDiffieHellman256Request = ^TDiffieHellman256Request;
  TDiffieHellman256Response = array[0..7] of TDiffieHellmanResponse;
  PDiffieHellman256Response = ^TDiffieHellman256Response;

  { TDiffieHellman256 }

  TDiffieHellman256 = class(TObject)
    private
      A: array[0..7] of TDiffieHellman;
      function GetKey: TKey256;
    public
      constructor Create;
      destructor Destroy; override;
      procedure Clear;
      function GenerateRequest: TDiffieHellman256Request;
      function ProcessRequest(Request: TDiffieHellman256Request): TDiffieHellman256Response;
      procedure ReceiveResponse(Response: TDiffieHellman256Response);
      function KeysMatch(DH: TDiffieHellman256): Boolean;
      property Key: TKey256 read GetKey;
  end;

function DHRequestToStr(Request: TDiffieHellmanRequest): String;
function DHResponseToStr(Response: TDiffieHellmanResponse): String;
function DH128RequestToStr(Request: TDiffieHellman128Request): String;
function DH128ResponseToStr(Response: TDiffieHellman128Response): String;
function DH256RequestToStr(Request: TDiffieHellman256Request): String;
function DH256ResponseToStr(Response: TDiffieHellman256Response): String;

implementation

uses
  Rand;

function DHRequestToStr(Request: TDiffieHellmanRequest): String;
begin
  Result := Format('Generator=%s Interim=%s Modulus=%s',[
    BufferToHex(@Request.Generator,SizeOf(Request.Generator)),
    BufferToHex(@Request.Interim,SizeOf(Request.Interim)),
    BufferToHex(@Request.Modulus,SizeOf(Request.Modulus))
  ]);
end;

function DHResponseToStr(Response: TDiffieHellmanResponse): String;
begin
  Result := Format('Interim=%s',[BufferToHex(@Response.Interim,SizeOf(Response.Interim))]);
end;

function DH128RequestToStr(Request: TDiffieHellman128Request): String;
begin
  Result := '[0] '+DHRequestToStr(Request[0])+#13#10+
            '[1] '+DHRequestToStr(Request[1])+#13#10+
            '[2] '+DHRequestToStr(Request[2])+#13#10+
            '[3] '+DHRequestToStr(Request[3])+#13#10;
end;

function DH128ResponseToStr(Response: TDiffieHellman128Response): String;
begin
  Result := '[0] '+DHResponseToStr(Response[0])+#13#10+
            '[1] '+DHResponseToStr(Response[1])+#13#10+
            '[2] '+DHResponseToStr(Response[2])+#13#10+
            '[3] '+DHResponseToStr(Response[3])+#13#10;
end;

function DH256RequestToStr(Request: TDiffieHellman256Request): String;
begin
  Result := '[0] '+DHRequestToStr(Request[0])+#13#10+
            '[1] '+DHRequestToStr(Request[1])+#13#10+
            '[2] '+DHRequestToStr(Request[2])+#13#10+
            '[3] '+DHRequestToStr(Request[3])+#13#10+
            '[4] '+DHRequestToStr(Request[4])+#13#10+
            '[5] '+DHRequestToStr(Request[5])+#13#10+
            '[6] '+DHRequestToStr(Request[6])+#13#10+
            '[7] '+DHRequestToStr(Request[7])+#13#10;
end;

function DH256ResponseToStr(Response: TDiffieHellman256Response): String;
begin
  Result := '[0] '+DHResponseToStr(Response[0])+#13#10+
            '[1] '+DHResponseToStr(Response[1])+#13#10+
            '[2] '+DHResponseToStr(Response[2])+#13#10+
            '[3] '+DHResponseToStr(Response[3])+#13#10+
            '[4] '+DHResponseToStr(Response[4])+#13#10+
            '[5] '+DHResponseToStr(Response[5])+#13#10+
            '[6] '+DHResponseToStr(Response[6])+#13#10+
            '[7] '+DHResponseToStr(Response[7])+#13#10;
end;

{ TDiffieHellman }

constructor TDiffieHellman.Create;
begin
  Clear;
end;

destructor TDiffieHellman.Destroy;
begin
  Clear;
  inherited Destroy;
end;

// Zeros everything except key
procedure TDiffieHellman.Clean;
begin
  FGenerator := 0; FModulus := 0;
  FPrivateA := 0; FPrivateB := 0;
  FInterimA := 0; FInterimB := 0;
end;

// Zeros everything
procedure TDiffieHellman.Clear;
begin
  Clean;
  FKey := 0;
end;

function TDiffieHellman.GenerateRequest: TDiffieHellmanRequest;
begin
  CreateKeys(Result.Generator,Result.Modulus);
  Result.Interim := CreateSenderInterKey;
end;

function TDiffieHellman.ProcessRequest(Request: TDiffieHellmanRequest): TDiffieHellmanResponse;
begin
  Result.Interim := CreateRecipientInterKey(Request.Generator,Request.Modulus);
  CreateRecipientEncryptionKey(Request.Interim);
  Clean;
end;

procedure TDiffieHellman.ReceiveResponse(Response: TDiffieHellmanResponse);
begin
  CreateSenderEncryptionKey(Response.Interim);
  Clean;
end;

procedure TDiffieHellman.CreateKeys(out Generator, Modulus: DWORD);
var
  Swap: DWORD;
begin
  FGenerator := GeneratePrime;
  FModulus := GeneratePrime;
  if FGenerator > FModulus then
    begin
      Swap := FGenerator;
      FGenerator := FModulus;
      FModulus := Swap;
    end;
  Generator := FGenerator;
  Modulus := FModulus;
end;

function TDiffieHellman.CreateSenderInterKey: DWORD;
begin
  FPrivateA := RNG.Generate;
  FInterimA := XpowYmodN(FGenerator,FPrivateA,FModulus);
  Result := FInterimA;
end;

function TDiffieHellman.CreateRecipientInterKey(Generator, Modulus: DWORD): DWORD;
begin
  FPrivateB  := RNG.Generate;
  FGenerator := Generator;
  FModulus   := Modulus;
  FInterimB  := XpowYmodN(FGenerator,FPrivateB,FModulus);
  Result     := FInterimB;
end;

procedure TDiffieHellman.CreateSenderEncryptionKey(RecipientInterKey: DWORD);
begin
  FInterimB := RecipientInterKey;
  FKey := XpowYmodN(FInterimB,FPrivateA,FModulus);
end;

procedure TDiffieHellman.CreateRecipientEncryptionKey(SenderInterKey: DWORD);
begin
  FInterimA := SenderInterKey;
  FKey := XpowYmodN(FInterimA,FPrivateB,FModulus);
end;

{ TDiffieHellman128 }

constructor TDiffieHellman128.Create;
var
  I: Byte;
begin
  for I := 0 to 3 do A[I] := TDiffieHellman.Create;
end;

destructor TDiffieHellman128.Destroy;
var
  I: Byte;
begin
  for I := 0 to 3 do A[I].Destroy;
  inherited Destroy;
end;

procedure TDiffieHellman128.Clear;
var
  I: Byte;
begin
  for I := 0 to 3 do A[I].Clear;
end;

function TDiffieHellman128.GetKey: TKey128;
var
  X: Byte;
  D: DWORD;
begin
  for X := 0 to 3 do
    begin
      D := A[X].Key;
      Result[X*4+0] := (D and $FF000000) shr 24;
      Result[X*4+1] := (D and $FF0000  ) shr 16;
      Result[X*4+2] := (D and $FF00    ) shr 8;
      Result[X*4+3] := (D and $FF      );
    end;
end;

function TDiffieHellman128.GenerateRequest: TDiffieHellman128Request;
var
  I: Byte;
begin
  for I := 0 to 3 do Result[I] := A[I].GenerateRequest;
end;

function TDiffieHellman128.ProcessRequest(Request: TDiffieHellman128Request): TDiffieHellman128Response;
var
  I: Byte;
begin
  for I := 0 to 3 do Result[I] := A[I].ProcessRequest(Request[I]);
end;

procedure TDiffieHellman128.ReceiveResponse(Response: TDiffieHellman128Response);
var
  I: Byte;
begin
  for I := 0 to 3 do A[I].ReceiveResponse(Response[I]);
end;

function TDiffieHellman128.KeysMatch(DH: TDiffieHellman128): Boolean;
var
  I: Integer;
  Key1, Key2: TKey128;
begin
  Key1 := Key;
  Key2 := DH.Key;
  for I := 0 to 15 do
    if Key1[I] <> Key2[I] then
      begin
        Result := False;
        Exit;
      end;
  Result := True;
end;

{ TDiffieHellman256 }

constructor TDiffieHellman256.Create;
var
  I: Byte;
begin
  for I := 0 to 7 do A[I] := TDiffieHellman.Create;
end;

destructor TDiffieHellman256.Destroy;
var
  I: Byte;
begin
  for I := 0 to 7 do A[I].Destroy;
  inherited Destroy;
end;

procedure TDiffieHellman256.Clear;
var
  I: Byte;
begin
  for I := 0 to 7 do A[I].Clear;
end;

function TDiffieHellman256.GetKey: TKey256;
var
  X: Byte;
  D: DWORD;
begin
  for X := 0 to 7 do
    begin
      D := A[X].Key;
      Result[X] := D;
{      Result[X*4+0] := (D and $FF000000) shr 24;
      Result[X*4+1] := (D and $FF0000  ) shr 16;
      Result[X*4+2] := (D and $FF00    ) shr 8;
      Result[X*4+3] := (D and $FF      );     }
    end;
end;

function TDiffieHellman256.GenerateRequest: TDiffieHellman256Request;
var
  I: Byte;
begin
  for I := 0 to 7 do Result[I] := A[I].GenerateRequest;
end;

function TDiffieHellman256.ProcessRequest(Request: TDiffieHellman256Request): TDiffieHellman256Response;
var
  I: Byte;
begin
  for I := 0 to 7 do Result[I] := A[I].ProcessRequest(Request[I]);
end;

procedure TDiffieHellman256.ReceiveResponse(Response: TDiffieHellman256Response);
var
  I: Byte;
begin
  for I := 0 to 7 do A[I].ReceiveResponse(Response[I]);
end;

function TDiffieHellman256.KeysMatch(DH: TDiffieHellman256): Boolean;
var
  I: Integer;
  Key1, Key2: TKey256;
begin
  Key1 := Key;
  Key2 := DH.Key;
  for I := 0 to 31 do
    if Key1[I] <> Key2[I] then
      begin
        Result := False;
        Exit;
      end;
  Result := True;
end;

end.

