unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  Crypto, CryptoUtils;

type

  { TMain }

  TMain = class(TForm)
    Algorithms: TComboBox;
    Memo: TMemo;
    Modes: TComboBox;
    procedure DoChanged(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { private declarations }
  public
    IV: TBlock128;
    Key: TBlock256;
  end;

var
  Main: TMain;

implementation

{$R *.lfm}

{ TMain }

procedure TMain.FormCreate(Sender: TObject);
var
  A: TCipherAlgorithm;
  M: TCipherMode;
begin
  Algorithms.Items.Clear;
  for A := Low(A) to High(A) do
    Algorithms.Items.Add(CIPHER_ALGORITHM_STR[A]);
  Modes.Items.Clear;
  for M := Low(M) to High(M) do
    Modes.Items.Add(CIPHER_MODE_STR[M]);
  Algorithms.ItemIndex := 0;
  Modes.ItemIndex := 0;
end;

procedure FillData(D: Pointer);
type
  TData = array[0..1023] of Byte;
var
  X,Y: Integer;
begin
  X := 1; Y := 0;
  while Y < 1024 do
    begin
      TData(D^)[Y] := X;
      inc(X);
      inc(Y);
      if X > 100 then X := 1;
    end;
end;

procedure TMain.DoChanged(Sender: TObject);
var
  A: TCipherAlgorithm;
  M: TCipherMode;
  C: TCipher;
  D: Pointer;
begin
  Memo.Clear;
  A := TCipherAlgorithm(Algorithms.ItemIndex);
  M := TCipherMode(Modes.ItemIndex);
  FillChar(Key,32,0);
  FillChar(IV,32,0);
  C := CreateCipher(A,@Key,256);
  C.InitMode(M,@IV);
  D := GetMem(1024);
  try
    FillData(D);
    //FillChar(D^,1024,0);
    C.Encrypt(D,1024);
    Memo.Lines.Add(BuffertoHex(D,1024));
    Memo.Lines.Add('');
    C.InitMode(M,@IV);
    C.Decrypt(D,1024);
    Memo.Lines.Add(BufferToHex(D,1024));
  finally
    FreeMem(D);
  end;
end;

end.

