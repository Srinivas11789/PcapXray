# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'qt_design2.ui'
#
# Created by: PyQt5 UI code generator 5.12.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow():
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(731, 536)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setGeometry(QtCore.QRect(10, 10, 711, 61))
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setGeometry(QtCore.QRect(10, 20, 131, 16))
        self.label.setObjectName("label")
        self.textEdit = QtWidgets.QTextEdit(self.frame)
        self.textEdit.setGeometry(QtCore.QRect(140, 20, 221, 21))
        self.textEdit.setObjectName("textEdit")
        self.pushButton = QtWidgets.QPushButton(self.frame)
        self.pushButton.setGeometry(QtCore.QRect(360, 10, 111, 41))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.browse_dir)
        self.pushButton_2 = QtWidgets.QPushButton(self.frame)
        self.pushButton_2.setGeometry(QtCore.QRect(470, 10, 101, 41))
        self.pushButton_2.setObjectName("pushButton_2")
        self.progressBar = QtWidgets.QProgressBar(self.frame)
        self.progressBar.setGeometry(QtCore.QRect(580, 10, 121, 41))
        self.progressBar.setProperty("value", 24)
        self.progressBar.setObjectName("progressBar")
        self.frame_2 = QtWidgets.QFrame(self.centralwidget)
        self.frame_2.setGeometry(QtCore.QRect(10, 80, 711, 61))
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.label_2 = QtWidgets.QLabel(self.frame_2)
        self.label_2.setGeometry(QtCore.QRect(10, 20, 141, 16))
        self.label_2.setObjectName("label_2")
        self.textEdit_2 = QtWidgets.QTextEdit(self.frame_2)
        self.textEdit_2.setGeometry(QtCore.QRect(150, 20, 211, 21))
        self.textEdit_2.setObjectName("textEdit_2")
        self.pushButton_4 = QtWidgets.QPushButton(self.frame_2)
        self.pushButton_4.setGeometry(QtCore.QRect(500, 10, 111, 41))
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_5 = QtWidgets.QPushButton(self.frame_2)
        self.pushButton_5.setGeometry(QtCore.QRect(600, 10, 111, 41))
        self.pushButton_5.setObjectName("pushButton_5")
        self.pushButton_3 = QtWidgets.QPushButton(self.frame_2)
        self.pushButton_3.setGeometry(QtCore.QRect(360, 10, 111, 41))
        self.pushButton_3.setObjectName("pushButton_3")
        self.frame_3 = QtWidgets.QFrame(self.centralwidget)
        self.frame_3.setGeometry(QtCore.QRect(10, 150, 711, 61))
        self.frame_3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setObjectName("frame_3")
        self.label_3 = QtWidgets.QLabel(self.frame_3)
        self.label_3.setGeometry(QtCore.QRect(10, 20, 51, 16))
        self.label_3.setObjectName("label_3")
        self.comboBox = QtWidgets.QComboBox(self.frame_3)
        self.comboBox.setGeometry(QtCore.QRect(60, 10, 121, 41))
        self.comboBox.setObjectName("comboBox")
        self.comboBox_2 = QtWidgets.QComboBox(self.frame_3)
        self.comboBox_2.setGeometry(QtCore.QRect(380, 10, 121, 41))
        self.comboBox_2.setObjectName("comboBox_2")
        self.comboBox_3 = QtWidgets.QComboBox(self.frame_3)
        self.comboBox_3.setGeometry(QtCore.QRect(240, 10, 111, 41))
        self.comboBox_3.setObjectName("comboBox_3")
        self.label_4 = QtWidgets.QLabel(self.frame_3)
        self.label_4.setGeometry(QtCore.QRect(360, 20, 31, 16))
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.frame_3)
        self.label_5.setGeometry(QtCore.QRect(200, 20, 41, 16))
        self.label_5.setObjectName("label_5")
        self.pushButton_6 = QtWidgets.QPushButton(self.frame_3)
        self.pushButton_6.setGeometry(QtCore.QRect(580, 10, 121, 41))
        self.pushButton_6.setObjectName("pushButton_6")
        self.frame_4 = QtWidgets.QFrame(self.centralwidget)
        self.frame_4.setGeometry(QtCore.QRect(10, 220, 711, 281))
        self.frame_4.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_4.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_4.setObjectName("frame_4")
        self.horizontalScrollBar = QtWidgets.QScrollBar(self.frame_4)
        self.horizontalScrollBar.setGeometry(QtCore.QRect(10, 260, 691, 16))
        self.horizontalScrollBar.setOrientation(QtCore.Qt.Horizontal)
        self.horizontalScrollBar.setObjectName("horizontalScrollBar")
        self.verticalScrollBar = QtWidgets.QScrollBar(self.frame_4)
        self.verticalScrollBar.setGeometry(QtCore.QRect(690, 10, 16, 241))
        self.verticalScrollBar.setOrientation(QtCore.Qt.Vertical)
        self.verticalScrollBar.setObjectName("verticalScrollBar")
        self.textEdit_3 = QtWidgets.QTextEdit(self.frame_4)
        self.textEdit_3.setGeometry(QtCore.QRect(10, 10, 671, 241))
        self.textEdit_3.setObjectName("textEdit_3")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        # Params
        self.pcap_filename = ""

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
    
    def browse_dir(self):
        self.pcap_filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', QtCore.QDir.rootPath() , '*.pcap*')
        self.textEdit.setText(self.pcap_filename)
        #if _ is not None:
        #    print("Select a file!")

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PcapXray"))
        self.label.setText(_translate("MainWindow", "Enter pcap file path:"))
        self.pushButton.setText(_translate("MainWindow", "Browse"))
        self.pushButton_2.setText(_translate("MainWindow", "Analyze!"))
        self.label_2.setText(_translate("MainWindow", "Output directory path:   "))
        self.pushButton_4.setText(_translate("MainWindow", "Zoom In"))
        self.pushButton_5.setText(_translate("MainWindow", "Zoom Out"))
        self.pushButton_3.setText(_translate("MainWindow", "Browse"))
        self.label_3.setText(_translate("MainWindow", "Traffic: "))
        self.label_4.setText(_translate("MainWindow", "To: "))
        self.label_5.setText(_translate("MainWindow", "From: "))
        self.pushButton_6.setText(_translate("MainWindow", "Visualize!"))
        self.textEdit_3.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'.SF NS Text\'; font-size:13pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-weight:600;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:600;\">Description:</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#060404;\">PcapXray tools is an aid for Network Forensics or Any Network Analysis!. </span><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">It is a tool aimed to simplyfy the network analysis and speed the process of analysing the network traffic.</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">This prototype aims to accomplish 4 important modules,</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">  1. Web Traffic</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">  2. Tor Traffic</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">  3. Malicious Traffic</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">  4. Device/Traffic Details</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">  5. Covert Communication</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\"><br /></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-family:\'Menlo,Monaco,Courier New,monospace\'; font-size:12px; color:#000000;\">Please contact me @ spg349@nyu.edu for any bugs or problems !</span></p></body></html>"))




if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
