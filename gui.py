import sys
import threading

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *

from lib.bottle import *
from utils import get_resource
import detector

TEMPLATE_PATH.insert(0, get_resource('gui'))
webapp = Bottle()

@webapp.route('/static/<path:path>')
def static(path):
    return static_file(path, get_resource('gui/static/'))

@webapp.route('/')
def index():
    return template('index', action='start')

@webapp.route('/scan')
def scan():
    scanner = threading.Thread(target=detector.main)
    scanner.daemon = True
    scanner.start()
    return template('index', action='scan')

class WebApp(QThread):
    def __init__(self):
        QThread.__init__(self)

    def run(self):
        run(webapp, host='localhost', port=31337, quiet=True)

class Window(QWebView):
    def __init__(self):
        QWebView.__init__(self)
        self.setWindowTitle('Detekt')
        self.resize(640, 400)
        self.setMinimumSize(640, 400)
        self.setMaximumSize(640, 400)
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
