program blockmodetests;

{$mode objfpc}{$H+}

uses
  Interfaces, Forms, GuiTestRunner, ctrtests, ofbtests, cfbtests;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

