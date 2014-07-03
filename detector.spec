# -*- mode: python -*-
a = Analysis(['gui.py'],
             pathex=[os.path.dirname(__file__)],
             hiddenimports=[],
             hookspath=None)

pyz = PYZ(a.pure)

#for folder in ['drivers', 'rules']:
#    for file_name in os.listdir(folder):
#        a.datas.append((file_name, os.path.join(folder, file_name), 'DATA'))

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          Tree('gui', prefix='gui'),
          Tree('drivers', prefix='drivers'),
          Tree('rules', prefix='rules'),
          name=os.path.join('dist', 'detector.exe'),
          debug=False,
          strip=False,
          upx=False,
          console=True,
          icon='magnify.exe,0')
