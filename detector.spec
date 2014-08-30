# -*- mode: python -*-

a = Analysis(['gui.py'],
              pathex=[os.path.dirname(__file__)])

pyz = PYZ(a.pure)

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
          console=True, # TODO: Turn to False when finished developing.
          icon='magnify.exe,0')
