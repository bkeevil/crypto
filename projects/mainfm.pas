unit mainfm;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  Grids, Crypto,
  DCPblowfish, DCPtwofish, DCPcast128, DCPcast256, DCPice, DCPidea, DCPdes,
  DCPrc2, DCPrc5, DCPrc6, DCPrijndael, DCPserpent, DCPtea,

  DCPhaval, DCPmd4, DCPmd5, DCPripemd128, DCPripemd160, DCPsha1, DCPsha256,
  DCPsha512, DCPtiger;

type

  { TForm1 }

  TForm1 = class(TForm)
    SelfTestBtn: TButton;
    Grid: TStringGrid;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure SelfTestBtnClick(Sender: TObject);
  private
    procedure TestCipher(AClass: TCipherClass);
    procedure TestCipherPerf(AClass: TCipherClass; Mode: TCipherMode; var EncPerf,
      DecPerf: Single; var ErrorCount: Integer);
    procedure TestHash(AClass: THashClass);
    procedure TestHashPerf(AClass: THashClass; var Perf: Single);
    { private declarations }
  public
    RandData: TMemoryStream;
  end;

var
  Form1: TForm1;

implementation

uses
  DateUtils, cryptoutils, Rand;

{$R *.lfm}

{ TForm1 }

procedure TForm1.TestHashPerf(AClass: THashClass; var Perf: Single);
var
  H: THash;
  D: Pointer;
  ST, ET: TDateTime;
begin
  H := AClass.Create;
  try
    D := GetMem(AClass.HashSize div 8);
    try
      ST := Now;
      H.Init;
      H.UpdateStream(RandData,RandData.Size);
      H.Final(D^);
      ET := Now;
      Perf := 1000 / MillisecondsBetween(ET,ST);
      RandData.Position := 0;
    finally
      FreeMem(D);
    end;
  finally
    H.Free;
  end;
end;

procedure TForm1.TestHash(AClass: THashClass);
var
  SelfTestResult: String;
  Perf: Single;
begin
  if AClass.SelfTest then
    SelfTestResult := 'Pass'
  else
    SelfTestResult := 'FAIL';
  TestHashPerf(AClass,Perf);
  Grid.InsertRowWithValues(Grid.RowCount,['Hash',HASH_ALGORITHM_STR[AClass.Algorithm],'',IntToStr(AClass.HashSize),'',SelfTestResult,Format('%.2f MB/S',[Perf]),'','']);
end;

function CountStreamDifferences(Stream1,Stream2: TStream): Integer;
var
  X: Integer;
  B1, B2: Byte;
begin
  Result := 0;
  if Stream1.Size <> Stream2.Size then
    Result := $7FFFFFFF
  else
    for X := 1 to Stream1.Size do
      begin
        Stream1.Read(B1,SizeOf(B1));
        Stream2.Read(B2,SizeOf(B2));
        if B1 <> B2 then
          inc(Result);
      end;
end;

procedure TForm1.TestCipherPerf(AClass: TCipherClass; Mode: TCipherMode; var EncPerf, DecPerf: Single; var ErrorCount: Integer);
var
  ST, ET: TDateTime;
  C: TCipher;
  K: Pointer;
  IVSize: Integer;
  IV: Pointer;
  Temp1,Temp2: TMemoryStream;
begin
  Temp1 := nil;
  Temp2 := nil;
  ErrorCount := 0;
  K := GetMem(AClass.MaxKeySize div 8);
  IVSize := AClass.BlockSize div 8;
  if IVSize > 0 then
    IV := GetMem(IVSize);
  try
    FillRandom(K,AClass.MaxKeySize div 8);
    if IVSize > 0 then
      FillRandom(IV,IVSize);
    C := AClass.Create(@K,AClass.MaxKeySize div 8);
    C.InitMode(Mode,@IV);
    Temp1 := TMemoryStream.Create;
    Temp2 := TMemoryStream.Create;
    try
      ST := Now;
      ET := Now;
      EncPerf := MillisecondsBetween(ET,ST);
      DecPerf := EncPerf;
      RandData.Position := 0;
      ST := Now;
      C.EncryptStream(RandData,Temp1);
      ET := Now;
      EncPerf := EncPerf + MillisecondsBetween(ET,ST);

      RandData.Position := 0;
      Temp1.Position := 0;
      ST := Now;
      C.InitMode(Mode,@IV);
      C.DecryptStream(Temp1,Temp2);
      ET := Now;
      DecPerf := DecPerf + MillisecondsBetween(ET,ST);
      Temp2.Position := 0;
      ErrorCount := CountStreamDifferences(RandData,Temp2);
      RandData.Position := 0;
    finally
      FreeAndNil(Temp1);
      FreeAndNil(Temp2);
    end;

  finally
    if IVSize > 0 then
      FreeMem(IV);
    FreeMem(K);
    C.Free;
  end;
  EncPerf := 1000 / EncPerf;
  DecPerf := 1000 / DecPerf;
end;

procedure TForm1.TestCipher(AClass: TCipherClass);
var
  SelfTestResult: String;
  Mode: TCipherMode; //cmCBC, cmCFB, cmOFB, cmCTR
  ModeStr: String;
  EncPerf: Single;
  DecPerf: Single;
  ErrorCount: Integer;
begin
  if AClass.SelfTest then
    SelfTestResult := 'Pass'
  else
    SelfTestResult := 'FAIL';
  for Mode := Low(Mode) to High(Mode) do
    begin
      ModeStr := CIPHER_MODE_STR[Mode];
      TestCipherPerf(AClass,Mode,EncPerf,DecPerf,ErrorCount);
      Grid.InsertRowWithValues(Grid.RowCount,['Cipher',CIPHER_ALGORITHM_STR[AClass.Algorithm],ModeStr,IntToStr(AClass.MaxKeySize),IntToStr(AClass.BlockSize),SelfTestResult,Format('%.2f MB/S',[EncPerf]),Format('%.2f MB/S',[DecPerf]),IntToStr(ErrorCount)]);
      Application.ProcessMessages;
      if ModeStr = 'Stream' then Exit;
    end;
end;

procedure TForm1.SelfTestBtnClick(Sender: TObject);
begin
  Grid.RowCount := 1;
  TestCipher(TCipherBlowfish); TestCipher(TCipherCAST128); TestCipher(TCipherCAST256); TestCipher(TCipherDES); TestCipher(TCipher3DES);
  TestCipher(TCipherICE); TestCipher(TCipherThinICE); TestCipher(TCipherICE2); TestCipher(TCipherIDEA);
  TestCipher(TCipherRC2); TestCipher(TCipherRC5); TestCipher(TCipherRC6); TestCipher(TCipherRijndael);
  TestCipher(TCipherSerpent); TestCipher(TCipherTEA); TestCipher(TCipherTwofish);
  TestHash(THashHaval); TestHash(THashMD4); TestHash(THashMD5); TestHash(THashRipeMD128); TestHash(THashRipeMD160);
  TestHash(THashSHA1); TestHash(THashSHA256); TestHash(THashSHA384); TestHash(THashSHA512); TestHash(THashTiger);
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  X: Integer;
  R: Cardinal;
begin
  RandData := TMemoryStream.Create;
  for X := 1 to 1024 * 1024 do
    begin
      R := RNG.Generate;
      RandData.Write(R,SizeOf(R));
    end;
  RandData.Position := 0;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  RandData.Free;
end;

end.

