# -*- mode: python -*-
def get_plugins(list):
    for item in list:
        if item[0].startswith('volatility.plugins') and not (item[0] == 'volatility.plugins' and '__init__.py' in item[1]):
            yield item

a = Analysis(['gui.py'],
              pathex=[os.path.dirname(__file__)],
              hookspath=['hooks'])

pyz = PYZ(a.pure)

volatility = Tree(os.path.join('volatility', 'volatility'),
                  prefix='volatility')

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          volatility,
          Tree('gui', prefix='gui'),
          Tree('drivers', prefix='drivers'),
          Tree('rules', prefix='rules'),
          name=os.path.join('dist', 'detekt.exe'),
          debug=False,
          strip=False,
          upx=False,
          console=False,
          icon='detekt.ico')
