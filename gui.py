import sys
import Queue
import threading

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *

from lib.bottle import *
from utils import get_resource, check_connection
import detector

TEMPLATE_PATH.insert(0, get_resource('gui'))
webapp = Bottle()

queue_results = Queue.Queue()
queue_errors = Queue.Queue()

scanner = threading.Thread(target=detector.main, args=(queue_results, queue_errors))
scanner.daemon = True

@webapp.route('/static/<path:path>')
def static(path):
    return static_file(path, get_resource('gui/static/'))

@webapp.route('/')
def index():
    connection = check_connection()
    return template('index', action='start', connection=connection)

@webapp.route('/scan')
def scan():
    scanner.start()
    return template('index', action='running')

@webapp.route('/check')
def check():
    if scanner.isAlive():
        return template('index', action='running')
    else:
        infected = False
        if queue_results.qsize() > 0:
            infected = True

        errors = []
        while True:
            try:
                errors.append(queue_errors.get(block=False))
            except Queue.Empty:
                break

        results = []
        while True:
            try:
                results.append(queue_results.get(block=False))
            except Queue.Empty:
                break

        return template('index', action='results', infected=infected,
                        errors=errors, results=results)

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
