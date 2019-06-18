import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from qt_design2 import Ui_MainWindow

class userInterfaceQt(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.setupUi(self)

    def browse(self):
        filename = QtGui.QFileDialog.getOpenFileName(self, 'Open File', '.')
        fname = open(filename)
        data = fname.read()
        self.textEdit.setText(data)
        fname.close()
    
    def browse_dir(self, option):
        if option == "output":
            self.report_dir = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
            self.textEdit_2.setText(self.report_dir)
            print(self.report_dir)
        else:
            #self.pcap_filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', QtCore.QDir.rootPath() , '*.pcap*')
            self.pcap_filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', "." , '*.pcap*')
            self.textEdit.setText(self.pcap_filename)
            print(self.pcap_filename)
            #if _ is not None:
            #    print("Select a file!")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = userInterfaceQt()
    window.show()
    sys.exit(app.exec_())