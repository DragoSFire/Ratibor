object MainForm: TMainForm
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = #1056#1072#1090#1080#1073#1086#1088#1077#1094
  ClientHeight = 291
  ClientWidth = 405
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 24
    Top = 24
    Width = 55
    Height = 13
    Caption = 'Process ID:'
  end
  object Label2: TLabel
    Left = 19
    Top = 64
    Width = 119
    Height = 13
    Caption = #1047#1072#1097#1080#1090#1080#1090#1100' '#1086#1090' '#1087#1088#1086#1094#1077#1089#1089#1072':'
  end
  object ProcessIDEdit: TEdit
    Left = 85
    Top = 21
    Width = 68
    Height = 21
    TabOrder = 0
    Text = '0'
  end
  object SelfProcessIDButton: TButton
    Left = 159
    Top = 19
    Width = 75
    Height = 25
    Caption = #1057#1074#1086#1081' ID'
    TabOrder = 1
    OnClick = SelfProcessIDButtonClick
  end
  object TargetProcessEdit: TEdit
    Left = 325
    Top = 61
    Width = 51
    Height = 21
    TabOrder = 2
    Text = '0'
  end
  object InjectToAllProcessesCheckBox: TCheckBox
    Left = 26
    Top = 249
    Width = 129
    Height = 17
    Caption = #1043#1083#1086#1073#1072#1083#1100#1085#1072#1103' '#1079#1072#1097#1080#1090#1072
    TabOrder = 3
    OnClick = InjectToAllProcessesCheckBoxClick
  end
  object InjectButton: TButton
    Left = 24
    Top = 201
    Width = 353
    Height = 41
    Caption = #1042#1099#1083#1077#1095#1080#1090#1100
    TabOrder = 4
    OnClick = InjectButtonClick
  end
  object UnInjectButton: TButton
    Left = 232
    Top = 248
    Width = 145
    Height = 25
    Caption = #1057#1085#1103#1090#1100' '#1087#1077#1088#1077#1093#1074#1072#1090
    TabOrder = 5
    OnClick = UnInjectButtonClick
  end
  object HideCheckbox: TCheckBox
    Left = 38
    Top = 178
    Width = 107
    Height = 17
    Caption = #1057#1082#1088#1099#1090#1100' '#1087#1088#1086#1094#1077#1089#1089
    TabOrder = 6
  end
  object FlushCheckbox: TCheckBox
    Left = 185
    Top = 178
    Width = 198
    Height = 17
    Caption = #1057#1090#1077#1088#1077#1090#1100' '#1080#1085#1092#1086#1088#1084#1072#1094#1080#1102' '#1086' '#1087#1088#1086#1094#1077#1089#1089#1077
    TabOrder = 7
  end
  object ConvertProcessNameToProcessIdButton: TButton
    Left = 294
    Top = 60
    Width = 28
    Height = 23
    Caption = '->'
    TabOrder = 8
    OnClick = ConvertProcessNameToProcessIdButtonClick
  end
  object RadioGroup: TRadioGroup
    Left = 68
    Top = 91
    Width = 269
    Height = 77
    Caption = #1055#1086#1076#1084#1077#1085#1072' ProcessID'
    Columns = 2
    ItemIndex = 0
    Items.Strings = (
      #1054#1088#1080#1075#1080#1085#1072#1083#1100#1085#1099#1081
      '9999'
      #1050#1072#1082' '#1091' '#1074#1099#1079#1099#1074#1072#1102#1097#1077#1075#1086' '#1087#1088#1086#1094#1077#1089#1089#1072
      #1057#1083#1091#1095#1072#1081#1085#1099#1081)
    TabOrder = 9
    WordWrap = True
  end
  object ProcessNameEdit: TEdit
    Left = 144
    Top = 61
    Width = 147
    Height = 21
    TabOrder = 10
    Text = 'Taskmgr.exe'
  end
  object SaveButton: TButton
    Left = 298
    Top = 19
    Width = 79
    Height = 25
    Caption = #1057#1086#1093#1088#1072#1085#1080#1090#1100
    TabOrder = 11
    OnClick = SaveButtonClick
  end
end
