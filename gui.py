import sys

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *

from lib.bottle import *
from utils import get_resource

TEMPLATE_PATH.insert(0, get_resource('gui'))
webapp = Bottle()

@webapp.route('/')
def index():
    return template('index')

class WebApp(QThread):
    def __init__(self):
        QThread.__init__(self)

    def run(self):
        run(webapp, host='localhost', port=31337, quiet=True)

class Window(QWebView):
    def __init__(self):
        QWebView.__init__(self)
        self.setWindowTitle('Detekt')
        self.resize(580, 400)
        self.setMinimumSize(580, 400)
        self.setMaximumSize(580, 400)
        #self.setWindowIcon(window_icon)
        self.load(QUrl('http://localhost:31337/'))

def main():
    app = QApplication(sys.argv)

    yo = WebApp()
    yo.start()

    win = Window()
    win.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
