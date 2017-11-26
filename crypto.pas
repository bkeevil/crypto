unit Crypto;

{$MODE Delphi}

interface

uses
  Classes, Sysutils, CryptoUtils;

type
  {$IFNDEF FPC}
  Pbyte= ^byte;
  Pword= ^word;
  Pdword= ^dword;
  Pint64= ^int64;
  dword= LongWord;
  Pwordarray= ^Twordarray;
  Twordarray= array[0..19383] of word;
  {$ENDIF}
  Pdwordarray= ^Tdwordarray;
  Tdwordarray= array[0..8191] of dword;

  TCipherAlgorithm  = (caNone, caBlowfish, caTwofish, caRC2, caRC5, caRC6, caDES, ca3DES, caCast128, caCast256, caRijndael, caIDEA, caICE, caThinICE, caICE2, caSerpent, caTEA);
  TCipherMode       = (cmCBC, cmCFB, cmOFB, cmCTR);
  THashAlgorithm    = (haNone, haMD4, haMD5, haSHA1, haSHA256, haSHA384, haSHA512, haRipeMD128, haRipeMD160, haHaval256, haTiger);

const
  CIPHER_ALGORITHM_STR: array[TCipherAlgorithm] of String = ('None','Blowfish','Twofish','RC2','RC5','RC6','DES','3DES','CAST-128','CAST-256','Rijndael','IDEA','ICE','ThinIce','ICE2','Serpent','TEA');
  CIPHER_MODE_STR: array[TCipherMode] of String = ('CBC','CFB','OFB','CTR');
  HASH_ALGORITHM_STR: array[THashAlgorithm] of String = ('None','MD4','MD5','SHA1','SHA-256','SHA-384','SHA-512','RipeMD-128','RipeMD-160','Haval-256','Tiger');

type
  TMAC128 = TBlock128;
  TMAC64  = TBlock64;

  TCipherModeBase = class;

  { THash }

  EHash= class(Exception);
  THash= class(TObject)
  protected
    FInitialized: Boolean;
  public
    destructor Destroy; override;
    //
    class function Algorithm: THashAlgorithm; virtual; abstract;
    class function HashSize: Integer; virtual; abstract;
    class function SelfTest: Boolean; virtual; abstract;
    //
    procedure Init; virtual;
    procedure Final(var Digest); virtual; abstract;
    procedure Burn; virtual;
    procedure Update(const Buffer; Size: LongWord); virtual; abstract;
    procedure UpdateStream(Stream: TStream; Size: LongWord);
    procedure UpdateStr(const Str: String);
    //
    property Initialized: Boolean read FInitialized;
  end;
  THashClass= class of THash;

  { TCipher }

  ECipher= class(Exception);
  TCipher= class(TObject)
    private
      FMode: TCipherModeBase;
    protected
      procedure InitKey(const Key; Size: longword); virtual; abstract;
    public
      constructor Create(Key: Pointer; KeySize: Integer); virtual;
      destructor Destroy; override;
      //
      class function Algorithm: TCipherAlgorithm; virtual; abstract;
      class function MaxKeySize: Integer; virtual; abstract;
      class function SelfTest: Boolean; virtual; abstract;
      class function BlockSize: Integer; virtual; abstract;
      //
      procedure InitMode(Mode: TCipherMode; IV: Pointer);
      //
      procedure EncryptBlock(const InData; var OutData); virtual; abstract;
      procedure DecryptBlock(const InData; var OutData); virtual; abstract;
      procedure Encrypt(Data: Pointer; Size: Integer);
      procedure Decrypt(Data: Pointer; Size: Integer);
      procedure EncryptStream(InStream, OutStream: TStream);
      procedure DecryptStream(InStream, OutStream: TStream);
  end;
  TCipherClass= class of TCipher;

  { TCipherModeBase }

  TCipherModeBase = class(TObject)
    private
      FCipher: TCipher;
      FBlockSize: Word;         { In Bytes, not bits }
      FCV: Pointer;
      IncBlock: procedure(V: Pointer);
      XORBlock: procedure(A,B,R: Pointer);      { Pointer to XOR function BlockSize bytes }
      procedure EncryptBlock(InBlock, OutBlock: Pointer);   { Encrypts BlockSize bytes }
      procedure DecryptBlock(InBlock, OutBlock: Pointer);   { Decrypts BlockSize bytes }
    public
      constructor Create(Cipher: TCipher; IV: Pointer);
      destructor Destroy; override;
      procedure Encrypt(Data: Pointer; Size: Integer); virtual; abstract;
      procedure Decrypt(Data: Pointer; Size: Integer); virtual; abstract;
      procedure EncryptStream(InStream, OutStream: TStream);
      procedure DecryptStream(InStream, OutStream: TStream);
  end;

  { TCipherOFBMode }

  TCipherOFBMode = class(TCipherModeBase)
    private
      FCVOffset: Byte;
      procedure Process(Data: Pointer; Size: Integer);
      procedure ProcessFirstBlock(var Data: Pointer; var Size: Integer);
      procedure ProcessLastBlock(Data: Pointer; Size: Integer);
      procedure ProcessMiddleBlock(var Data: Pointer; var Size: Integer);
    public
      procedure Encrypt(Data: Pointer; Size: Integer); override;
      procedure Decrypt(Data: Pointer; Size: Integer); override;
  end;

  { TCipherCFBMode }

  TCipherCFBMode = class(TCipherModeBase)
    private
      FEV: Pointer;
      FEVOffset: Byte;
      procedure EncryptFirstBlock(var Data: Pointer; var Size: Integer);
      procedure EncryptLastBlock(Data: Pointer; Size: Integer);
      procedure EncryptMiddleBlock(var Data: Pointer; var Size: Integer);
      procedure DecryptFirstBlock(var Data: Pointer; var Size: Integer);
      procedure DecryptLastBlock(Data: Pointer; Size: Integer);
      procedure DecryptMiddleBlock(var Data: Pointer; var Size: Integer);
    public
      constructor Create(Cipher: TCipher; IV: Pointer);
      destructor Destroy; override;
      procedure Encrypt(Data: Pointer; Size: Integer); override;
      procedure Decrypt(Data: Pointer; Size: Integer); override;
  end;

  { TCipherCTRMode }

  TCipherCTRMode = class(TCipherModeBase)
    private
      FEV: Pointer;
      FEVOffset: Byte;
      procedure Process(Data: Pointer; Size: Integer);
      procedure ProcessFirstBlock(var Data: Pointer; var Size: Integer);
      procedure ProcessLastBlock(Data: Pointer; Size: Integer);
      procedure ProcessMiddleBlock(var Data: Pointer; var Size: Integer);
    public
      constructor Create(Cipher: TCipher; IV: Pointer);
      destructor Destroy; override;
      procedure Encrypt(Data: Pointer; Size: Integer); override;
      procedure Decrypt(Data: Pointer; Size: Integer); override;
  end;

  { TCipherCBCMode }

  TCipherCBCMode = class(TCipherModeBase)
    private

    public
      procedure Encrypt(Data: Pointer; Size: Integer); override;
      procedure Decrypt(Data: Pointer; Size: Integer); override;
  end;

function CipherClass(Kind: TCipherAlgorithm): TCipherClass;
function CreateCipher(Kind: TCipherAlgorithm; Key: Pointer; KeySize: Integer): TCipher;
function CreateHash(Kind: THashAlgorithm = haSHA1): THash;
function MD5String(Str: String): TBlock128;
function SHA256String(Str: String): TBlock256;
function EncryptPassword(Password: String): String;
function DecryptPassword(Password: String): String;
function HMAC128(Algorithm: THashAlgorithm; Data: Pointer; DataSize: Integer; Key: Pointer; KeySize: Integer): TMAC128;
function HMAC64(Algorithm: THashAlgorithm; Data: Pointer; DataSize: Integer; Key: Pointer; KeySize: Integer): TMAC64;

implementation

uses
  Base64,
  DCPBlowfish, DCPTwoFish, DCPCast128, DCPCast256, DCPDES, DCPICE, DCPIdea, DCPRC2, DCPRC5, DCPRC6,
  DCPRijndael, DCPSerpent, DCPTEA,

  DCPHaval, DCPMD4, DCPMD5, DCPRipeMD128, DCPRipeMD160,
  DCPSHA1, DCPSHA256, DCPSHA512, DCPTiger;

const
  STR_NOT_INITIALIZED = 'Cipher mode not initialized';

var
  SystemKey: TBlock128 = (34912,11019,20129,61087);
  SystemIV : TBlock128 = (20045,23212,4212,45781);

function CipherClass(Kind: TCipherAlgorithm): TCipherClass;
begin
  case Kind of
    caBlowfish : Result := TCipherBlowfish;
    caTwofish  : Result := TCipherTwofish;
    caRC2      : Result := TCipherRC2;
    caRC5      : Result := TCipherRC5;
    caRC6      : Result := TCipherRC6;
    caDES      : Result := TCipherDES;
    ca3DES     : Result := TCipher3DES;
    caCast128  : Result := TCipherCast128;
    caCast256  : Result := TCipherCast256;
    caRijndael : Result := TCipherRijndael;
    caIDEA     : Result := TCipherIDEA;
    caICE      : Result := TCipherICE;
    caThinICE  : Result := TCipherThinICE;
    caICE2     : Result := TCipherICE2;
    caSerpent  : Result := TCipherSerpent;
    caTEA      : Result := TCipherTEA;
  else
    raise ECipher.Create('Cipher not found');
  end;
end;

function CreateCipher(Kind: TCipherAlgorithm; Key: Pointer; KeySize: Integer): TCipher;
begin
  CipherClass(Kind).Create(Key,KeySize);
end;

function CreateHash(Kind: THashAlgorithm): THash;
begin
  case Kind of
    haNone      : Result := nil;
    haMD4       : Result := THashMD4.Create;
    haMD5       : Result := THashMD5.Create;
    haSHA1      : Result := THashSHA1.Create;
    haSHA256    : Result := THashSHA256.Create;
    haSHA384    : Result := THashSHA384.Create;
    haSHA512    : Result := THashSHA512.Create;
    haRipeMD128 : Result := THashRipeMD128.Create;
    haRipeMD160 : Result := THashRipeMD160.Create;
    haHaval256  : Result := THashHaval.Create;
    haTiger     : Result := THashTiger.Create;
  else
    raise EHash.Create('Hash algorithm not found');
  end;
end;

procedure Hash(Algorithm: THashAlgorithm; Data: Pointer; DataSize: Integer; out Hash: Pointer; out HashSize: Integer);
var
  H: THash;
begin
  H := CreateHash(Algorithm);
  HashSize := H.HashSize div 8;
  Hash := GetMem(HashSize);
  try
    H.Init;
    H.Update(Data^,DataSize);
    H.Final(Hash^);
    H.Burn;
  finally
    H.Free;
  end;
end;

function MD5String(Str: String): TBlock128;
var
  Hash: THash;
  Digest: Pointer;
  Size: Integer;
begin
  Size := Hash.HashSize div 8;
  FillChar(Result,SizeOf(Result),0);
  Hash := CreateHash(haMD5);
  GetMem(Digest,Size);
  try
    Hash.Init;
    Hash.UpdateStr(Str);
    Hash.Final(Digest);
    if Size > Length(Result) then
      Size := Length(Result);
    Move(Digest^,Result,Size);
  finally
    FreeMem(Digest);
    Hash.Free;
  end;
end;

function SHA256String(Str: String): TBlock256;
var
  Hash: THash;
  Digest: Pointer;
  Size: Integer;
begin
  Size := Hash.HashSize div 8;
  FillChar(Result,SizeOf(Result),0);
  Hash := CreateHash(haSHA256);
  GetMem(Digest,Size);
  try
    Hash.Init;
    Hash.UpdateStr(Str);
    Hash.Final(Digest);
    if Size > Length(Result) then
      Size := Length(Result);
    Move(Digest^,Result,Size);
  finally
    FreeMem(Digest);
    Hash.Free;
  end;
end;

function EncryptPassword(Password: String): String;
var
  Cipher: TCipher;
  Mode: TCipherCFBMode;
  Data: String;
begin
  Data := Password;
  Cipher := CreateCipher(caBlowfish,@SystemKey,SizeOf(SystemKey));
  try
    Mode := TCipherCFBMode.Create(Cipher,@SystemIV);
    try
      Mode.Encrypt(PChar(Data),Length(Data));
      Result := EncodeStringBase64(Data);
    finally
      Mode.Free;
    end;
  finally
    Cipher.Free;
  end;
end;

function DecryptPassword(Password: String): String;
var
  Cipher: TCipher;
  Mode: TCipherCFBMode;
begin
  Cipher := CreateCipher(caBlowfish,@SystemKey,SizeOf(SystemKey));
  try
    Mode := TCipherCFBMode.Create(Cipher,@SystemIV);
    try
      if Password = '' then
        Result := ''
      else
        Result := DecodeStringBase64(Password);
      Mode.Decrypt(PChar(Result),Length(Result));
    finally
      Mode.Free;
    end;
  finally
    Cipher.Free;
  end;
end;

function HMAC128(Algorithm: THashAlgorithm; Data: Pointer; DataSize: Integer; Key: Pointer; KeySize: Integer): TMAC128;
var
  H: THash;
  IKey: Pointer;
  IKeySize: Integer;
  FreeIKey: Boolean;
  IPad: Pointer;
  OPad: Pointer;
  Digest: Pointer;
begin
  // If the key size is over 64 bytes long then use a hash of it instead
  if KeySize > 64 then
    begin
      Hash(Algorithm,Key,KeySize,IKey,IKeySize);
      FreeIKey := True;
    end
  else
    begin
      IKey := Key;
      IKeySize := KeySize;
      FreeIKey := False;
    end;
  try
    IPad := GetMem(64);
    OPad := GetMem(64);
    try
      Assert(KeySize <= 64);
      FillChar(IPad^,64,$36);
      XORMem(IPad,Key,IPad,KeySize);
      FillChar(OPad^,64,$5C);
      XORMem(OPad,Key,OPad,KeySize);
      H := CreateHash(Algorithm);
      try
        Assert(H.HashSize mod 8 = 0);
        Digest := GetMem(H.HashSize div 8);
        try
          H.Init;
          H.Update(IPad^,64);
          H.Update(Data^,DataSize);
          H.Final(Digest^);
          H.Burn;
          H.Init;
          H.Update(OPad^,64);
          H.Update(Digest^,H.HashSize div 8);
          H.Final(Digest^);
          Move(Digest^,Result,SizeOf(Result));
          H.Burn;
        finally
          FreeMem(Digest);
        end;
      finally
        FreeAndNil(H);
      end;
    finally
      FreeMem(IPad);
      FreeMem(OPad);
    end;
  finally
    if FreeIKey then
      FreeMem(IKey);
  end;
end;

function HMAC64(Algorithm: THashAlgorithm; Data: Pointer; DataSize: Integer; Key: Pointer; KeySize: Integer): TMAC64;
var
  MAC128: TMAC128;
begin
  MAC128 := HMAC128(Algorithm,Data,DataSize,Key,KeySize);
  Result[0] := MAC128[0];
  Result[1] := MAC128[1];
end;

{ TCipherCBCMode }

procedure TCipherCBCMode.Encrypt(Data: Pointer; Size: Integer);
var
  X: Integer;
begin
  if Size mod FBlockSize > 0 then
    raise Exception.Create('CBC mode only operates on full blocks');
  for X := 1 to Size div FBlocksize do
    begin
      XORBlock(Data,FCV,Data);
      EncryptBlock(Data,Data);
      Move(Data^,FCV^,FBlockSize);
      Data := Pointer(PtrUInt(Data) + FBlockSize);
    end;
end;

procedure TCipherCBCMode.Decrypt(Data: Pointer; Size: Integer);
var
  X: Integer;
  Temp: Pointer;
begin
  if Size mod FBlockSize > 0 then
    raise Exception.Create('CBC mode only operates on full blocks');
  Temp := GetMem(FBlockSize);
  try
    for X := 1 to Size div FBlocksize do
      begin
        Move(Data^,Temp^,FBlockSize);
        DecryptBlock(Data,Data);
        XORBlock(Data,FCV,Data);
        Move(Temp^,FCV^,FBlockSize);
        Data := Pointer(PtrUInt(Data) + FBlockSize);
      end;
  finally
    FreeMem(Temp);
  end;
end;

{$Q-}{$R-}

{ THash }

procedure THash.UpdateStream(Stream: TStream; Size: LongWord);
var
  Buffer: array[0..8191] of byte;
  i, read: Integer;
begin
  FillChar(Buffer, SizeOf(Buffer), 0);
  for i:= 1 to (Size div Sizeof(Buffer)) do
  begin
    read:= Stream.Read(Buffer,Sizeof(Buffer));
    Update(Buffer,read);
  end;
  if (Size mod Sizeof(Buffer))<> 0 then
  begin
    read:= Stream.Read(Buffer,Size mod Sizeof(Buffer));
    Update(Buffer,read);
  end;
end;

procedure THash.UpdateStr(const Str: String);
begin
  Update(Str[1],Length(Str));
end;

destructor THash.Destroy;
begin
  if fInitialized then
    Burn;
  inherited Destroy;
end;

procedure THash.Init;
begin
  FInitialized := True;
end;

procedure THash.Burn;
begin
  FInitialized := False;
end;

{ TCipher }

constructor TCipher.Create(Key: Pointer; KeySize: Integer);
begin
  inherited Create;
  if (KeySize <= 0) or (KeySize > MaxKeySize) then
    raise ECipher.Create('Invalid key size');
  InitKey(Key^,KeySize);
end;

destructor TCipher.Destroy;
begin
  if Assigned(FMode) then
    FMode.Free;
  inherited Destroy;
end;

procedure TCipher.InitMode(Mode: TCipherMode; IV: Pointer);
begin
  if Assigned(FMode) then
    FreeAndNil(FMode);
  case Mode of
    cmCBC: FMode := TCipherCBCMode.Create(Self,IV);
    cmCTR: FMode := TCipherCTRMode.Create(Self,IV);
    cmCFB: FMode := TCipherCFBMode.Create(Self,IV);
    cmOFB: FMode := TCipherOFBMode.Create(Self,IV);
  end;
end;

procedure TCipher.Encrypt(Data: Pointer; Size: Integer);
begin
  if Assigned(FMode) then
    FMode.Encrypt(Data,Size)
  else
    raise Exception.Create(STR_NOT_INITIALIZED);
end;

procedure TCipher.Decrypt(Data: Pointer; Size: Integer);
begin
  if Assigned(FMode) then
    FMode.Decrypt(Data,Size)
  else
    raise Exception.Create(STR_NOT_INITIALIZED);
end;

procedure TCipher.EncryptStream(InStream, OutStream: TStream);
begin
  if Assigned(FMode) then
    FMode.EncryptStream(InStream,OutStream)
  else
    raise Exception.Create(STR_NOT_INITIALIZED);
end;

procedure TCipher.DecryptStream(InStream, OutStream: TStream);
begin
  if Assigned(FMode) then
    FMode.DecryptStream(InStream,OutStream)
  else
    raise Exception.Create(STR_NOT_INITIALIZED);
end;

{ TCipherModeBase }

constructor TCipherModeBase.Create(Cipher: TCipher; IV: Pointer);
begin
  inherited Create;
  FCipher := Cipher;
  FBlockSize := FCipher.BlockSize;
  case FBlockSize of
    64  : begin
      XORBlock := @XOR64;
      IncBlock := @Inc64;
    end;
    128 : begin
      XORBlock := @XOR128;
      IncBlock := @Inc128;
    end
  else
    raise Exception.Create('Invalid block size');
  end;
  FBlockSize := FBlockSize div 8;
  GetMem(FCV,FBlockSize);
  if IV <> nil then
    Move(IV^,FCV^,FBlockSize);
end;

destructor TCipherModeBase.Destroy;
begin
  FreeMem(FCV,FBlockSize);
  inherited Destroy;
end;

procedure TCipherModeBase.EncryptStream(InStream, OutStream: TStream);
var
  B: Pointer;
  Size: Integer;
begin
  Size := 4096;
  GetMem(B,Size);
  while InStream.Size - InStream.Position > Size do
    begin
      InStream.Read(B^,Size);
      Encrypt(B,Size);
      OutStream.Write(B^,Size);
    end;
  Size := InStream.Size - InStream.Position;
  InStream.Read(B^,Size);
  Encrypt(B,Size);
  OutStream.Write(B^,Size);
  FreeMem(B);
end;

procedure TCipherModeBase.DecryptStream(InStream, OutStream: TStream);
var
  B: Pointer;
  Size: Integer;
begin
  Size := 4096;
  GetMem(B,Size);
  while InStream.Size - InStream.Position > Size do
    begin
      InStream.Read(B^,Size);
      Decrypt(B,Size);
      OutStream.Write(B^,Size);
    end;
  Size := InStream.Size - InStream.Position;
  InStream.Read(B^,Size);
  Decrypt(B,Size);
  OutStream.Write(B^,Size);
  FreeMem(B);
end;

procedure TCipherModeBase.EncryptBlock(InBlock, OutBlock: Pointer);
begin
  FCipher.EncryptBlock(InBlock^,OutBlock^);
end;

procedure TCipherModeBase.DecryptBlock(InBlock, OutBlock: Pointer);
begin
  FCipher.DecryptBlock(InBlock^,OutBlock^);
end;

{ TCipherOFBMode }

procedure TCipherOFBMode.ProcessFirstBlock(var Data: Pointer; var Size: Integer);
var
  C: Pointer;
  L: Integer;
begin
  // Calculate the length of data to be processed
  L := FBlockSize - FCVOffset;
  if L > Size then
    L := Size;
  // Get a pointer to the portion of the current vector that hasn't been used up yet
  C := Pointer(PtrUInt(FCV)+FCVOffset);
  // XOR with data
  XORMem(Data,C,Data,L);
  // Adjust Data and Size
  Size := Size - L;
  Data := Pointer(PtrUInt(Data) + L);
  FCVOffset := FCVOffset + L;
  if FCVOffset = FBlockSize then
    FCVOffset := 0;
end;

procedure TCipherOFBMode.ProcessMiddleBlock(var Data: Pointer; var Size: Integer);
begin
  // Encrypt vector and XOR with the next data block
  EncryptBlock(FCV,FCV);
  XORBlock(Data,FCV,Data);
  // Adjust Data and Size
  Size := Size - FBlockSize;
  Data := Pointer(PtrUInt(Data) + FBlockSize);
end;

procedure TCipherOFBMode.ProcessLastBlock(Data: Pointer; Size: Integer);
begin
  EncryptBlock(FCV,FCV);
  XORMem(Data,FCV,Data,Size);
  // The tail end of the current vector will be used in the next Encrypt operation
  FCVOffset := Size;
end;

procedure TCipherOFBMode.Process(Data: Pointer; Size: Integer);
begin
  if FCVOffset > 0 then
    ProcessFirstBlock(Data,Size);         { Data and Size parameters are adjusted by these funcs }
  while Size >= FBlockSize do
    ProcessMiddleBlock(Data,Size);
  if Size > 0 then
    ProcessLastBlock(Data,Size);
end;

procedure TCipherOFBMode.Encrypt(Data: Pointer; Size: Integer);
begin
  Process(Data,Size);
end;

procedure TCipherOFBMode.Decrypt(Data: Pointer; Size: Integer);
begin
  Process(Data,Size);
end;

{ TCipherCFBMode }

constructor TCipherCFBMode.Create(Cipher: TCipher; IV: Pointer);
begin
  inherited Create(Cipher,IV);
  FEV := GetMem(FBlockSize);
end;

destructor TCipherCFBMode.Destroy;
begin
  FreeMem(FEV);
  inherited Destroy;
end;

procedure TCipherCFBMode.EncryptFirstBlock(var Data: Pointer; var Size: Integer);
var
  C: Pointer;
  L: Integer;
begin
  // Calculate the length of data to be processed
  L := FBlockSize - FEVOffset;
  if L > Size then
    L := Size;
  // Get a pointer to the portion of the current vector that hasn't been used up yet
  C := Pointer(PtrUInt(FEV)+FEVOffset);
  // XOR with data
  XORMem(Data,C,Data,L);
  // Fill in the tail part of the CV vector
  C := Pointer(PtrUInt(FCV)+FEVOffset);
  Move(Data^,C^,L);
  // Adjust Data and Size
  Size := Size - L;
  Data := Pointer(PtrUInt(Data) + L);
  FEVOffset := FEVOffset + L;
  if FEVOffset = FBlockSize then
    FEVOffset := 0;
end;

procedure TCipherCFBMode.EncryptMiddleBlock(var Data: Pointer; var Size: Integer);
begin
  // Encrypt vector and XOR with the next data block
  EncryptBlock(FCV,FEV);
  XORBlock(Data,FEV,Data);
  Move(Data^,FCV^,FBlockSize);
  // Adjust Data and Size
  Size := Size - FBlockSize;
  Data := Pointer(PtrUInt(Data) + FBlockSize);
end;

procedure TCipherCFBMode.EncryptLastBlock(Data: Pointer; Size: Integer);
begin
  EncryptBlock(FCV,FEV);
  XORMem(Data,FEV,Data,Size);
  // The tail end of the current vector will be used in the next Encrypt operation
  FEVOffset := Size;
  Move(Data^,FCV^,Size); { Store for next operation }
end;

procedure TCipherCFBMode.Encrypt(Data: Pointer; Size: Integer);
begin
  if FEVOffset > 0 then
    EncryptFirstBlock(Data,Size);         { Data and Size parameters are adjusted by these funcs }
  while Size >= FBlockSize do
    EncryptMiddleBlock(Data,Size);
  if Size > 0 then
    EncryptLastBlock(Data,Size);
end;

procedure TCipherCFBMode.DecryptFirstBlock(var Data: Pointer; var Size: Integer);
var
  C: Pointer;
  L: Integer;
begin
  // Calculate the length of data to be processed
  L := FBlockSize - FEVOffset;
  if L > Size then
    L := Size;
  // Fill in the tail part of the CV vector
  C := Pointer(PtrUInt(FCV)+FEVOffset);
  Move(Data^,C^,L);
  // Get a pointer to the portion of the current vector that hasn't been used up yet
  C := Pointer(PtrUInt(FEV)+FEVOffset);
  // XOR with data
  XORMem(Data,C,Data,L);
  // Adjust Data and Size
  Size := Size - L;
  Data := Pointer(PtrUInt(Data) + L);
  FEVOffset := FEVOffset + L;
  if FEVOffset = FBlockSize then
    FEVOffset := 0;
end;

procedure TCipherCFBMode.DecryptMiddleBlock(var Data: Pointer; var Size: Integer);
begin
  // Encrypt vector and XOR with the next data block
  EncryptBlock(FCV,FEV);
  Move(Data^,FCV^,FBlockSize);
  XORBlock(Data,FEV,Data);
  // Adjust Data and Size
  Size := Size - FBlockSize;
  Data := Pointer(PtrUInt(Data) + FBlockSize);
end;

procedure TCipherCFBMode.DecryptLastBlock(Data: Pointer; Size: Integer);
begin
  EncryptBlock(FCV,FEV);
  Move(Data^,FCV^,Size);
  XORMem(Data,FEV,Data,Size);
  FEVOffset := Size;
end;

procedure TCipherCFBMode.Decrypt(Data: Pointer; Size: Integer);
begin
  if FEVOffset > 0 then
    DecryptFirstBlock(Data,Size);         { Data and Size parameters are adjusted by these funcs }
  while Size >= FBlockSize do
    DecryptMiddleBlock(Data,Size);
  if Size > 0 then
    DecryptLastBlock(Data,Size);
end;

{ TCipherCTRMode }

constructor TCipherCTRMode.Create(Cipher: TCipher; IV: Pointer);
begin
  inherited Create(Cipher,IV);
  FEV := GetMem(FBlockSize);
end;

destructor TCipherCTRMode.Destroy;
begin
  FreeMem(FEV);
  inherited Destroy;
end;

procedure TCipherCTRMode.ProcessFirstBlock(var Data: Pointer; var Size: Integer);
var
  C: Pointer;
  L: Integer;
begin
  // Calculate the length of data to be processed
  L := FBlockSize - FEVOffset;
  if L > Size then
    L := Size;
  // Get a pointer to the portion of the current vector that hasn't been used up yet
  C := Pointer(PtrUInt(FEV)+FEVOffset);
  // XOR with data
  XORMem(Data,C,Data,L);
  // Adjust Data and Size
  Size := Size - L;
  Data := Pointer(PtrUInt(Data) + L);
  FEVOffset := FEVOffset + L;
  if FEVOffset = FBlockSize then
    FEVOffset := 0;
end;

procedure TCipherCTRMode.ProcessMiddleBlock(var Data: Pointer; var Size: Integer);
begin
  // Encrypt vector and XOR with the next data block
  EncryptBlock(FCV,FEV);
  IncBlock(FCV);
  XORBlock(Data,FEV,Data);
  // Adjust Data and Size
  Size := Size - FBlockSize;
  Data := Pointer(PtrUInt(Data) + FBlockSize);
end;

procedure TCipherCTRMode.ProcessLastBlock(Data: Pointer; Size: Integer);
begin
  EncryptBlock(FCV,FEV);
  IncBlock(FCV);
  XORMem(Data,FEV,Data,Size);
  // The tail end of the current vector will be used in the next Encrypt operation
  FEVOffset := Size;
end;

procedure TCipherCTRMode.Process(Data: Pointer; Size: Integer);
begin
  if FEVOffset > 0 then
    ProcessFirstBlock(Data,Size);         { Data and Size parameters are adjusted by these funcs }
  while Size >= FBlockSize do
    ProcessMiddleBlock(Data,Size);
  if Size > 0 then
    ProcessLastBlock(Data,Size);
end;

procedure TCipherCTRMode.Encrypt(Data: Pointer; Size: Integer);
begin
  Process(Data,Size);
end;

procedure TCipherCTRMode.Decrypt(Data: Pointer; Size: Integer);
begin
  Process(Data,Size);
end;

end.

