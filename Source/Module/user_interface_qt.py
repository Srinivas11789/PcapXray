# Qt
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIcon, QPixmap
from user_interface_design import Ui_MainWindow

# Imports migrated from user interface
import pcap_reader
import plot_lan_network
import communication_details_fetch
import device_details_fetch
import report_generator
import time
import threading
import memory
from PIL import Image,ImageTk
import os, sys
from functools import partial

class userInterfaceQt(QtWidgets.QMainWindow, Ui_MainWindow):

    def __init__(self):

        # Params Declaration
        self.pcap_filename = ""
        self.report_dir = sys.path[0]+"/"
        self.zoom = [900,900]
        self.filename = ""

        # UI Setup
        QtWidgets.QMainWindow.__init__(self)
        self.setupUi(self)
        self.textEdit_2.setText(self.report_dir)
        self.connect_functions()
    
    def connect_functions(self):
        self.pushButton.clicked.connect(partial(self.browse_dir,""))
        self.pushButton_3.clicked.connect(partial(self.browse_dir,"output"))
        self.pushButton_2.clicked.connect(self.pcap_analyse)
        self.pushButton_6.clicked.connect(self.map_select)
    
    def browse_dir(self, option):
        if option == "output":
            self.report_dir = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
            self.textEdit_2.setText(self.report_dir)
            print(self.report_dir)
        else:
            self.pcap_filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', "." , '*.pcap*')
            self.filename = self.pcap_filename.replace(".pcap","")
            if "/" in self.filename:
                self.filename = self.filename.split("/")[-1]
            self.textEdit.setText(self.pcap_filename)
            print(self.pcap_filename)

    def pcap_analyse(self):

        if not os.access(self.report_dir, os.W_OK):
            QtWidgets.QErrorMessage().showMessage("Error","Permission denied to create report! Run with higher privilege.")
            return

        if os.path.exists(self.pcap_filename):
            
            # Disable controls when performing analysis
            self.pushButton_6.setEnabled(False)
            self.comboBox_2.setEnabled(False)
            self.comboBox_3.setEnabled(False)

            #self.progressbar.start()

            # PcapRead - First of All!
            #result = q.Queue()
            packet_read = threading.Thread(target=pcap_reader.PcapEngine,args=(self.pcap_filename,"scapy"))
            packet_read.start()
            #while packet_read.is_alive():
            #    self.progressbar.update()
            packet_read.join()
            #self.progressbar.stop()

            # Report Generation of the PcapData
            
            
            #packet_read.join()
            #self.capture_read = result.get()
            reportThreadpcap = threading.Thread(target=report_generator.reportGen(self.report_dir, self.filename).packetDetails,args=())
            reportThreadpcap.start()
            #self.option.set("Tor")
            #self.option.trace("w",self.map_select)
            #self.option.set("Tor")
            
            # Reset
            self.details_fetch = 0
            self.to_hosts = ["All"]
            self.from_hosts = ["All"]


            # Default filter values
            #self.to_menu['values'] = self.to_hosts
            #self.from_menu['values'] = self.from_hosts
            #self.from_menu.set("All")
            #self.to_menu.set("All")
            #self.option.set("All")
            
            #self.progressbar.start()
            self.to_hosts += list(memory.destination_hosts.keys())
            for mac in list(memory.lan_hosts.keys()):
                #self.progressbar.update()
                self.from_hosts.append(memory.lan_hosts[mac]["ip"])
            self.to_hosts = list(set(self.to_hosts + self.from_hosts))
            #self.to_menu['values'] = self.to_hosts
            #self.from_menu['values'] = self.from_hosts
            #self.progressbar.stop()

            # Enable controls
            self.pushButton_6.setEnabled(True)
            self.comboBox_2.setEnabled(True)
            self.comboBox_3.setEnabled(True)
            print("Done")
        else:
            QtWidgets.QErrorMessage().showMessage("Error","File Not Found !")

    def load_image(self):
        #pic_holder = QtWidgets.QLabel(self)

        # New widget
        #pic_widget = QtWidgets.QWidget(self)
        #self.setCentralWidget(pic_widget)

        # Set scroll area
        #self.area = QtWidgets.QScrollArea(pic_widget)
        #print(self.image_file)
        self.pic_holder.setPixmap(QPixmap(self.image_file))
        #self.frame_4.setGeometry(QtCore.QRect(10, 10, 800, 400))
        #self.scrollArea.setGeometry(QtCore.QRect(10, 10, 800, 400))
        #self.centralwidget.adjustSize()
        #self.adjustSize()
        #self.area.setWidget(pic_widget)
        #layout = QtWidgets.QVBoxLayout(self.area)
        #layout.addWidget(self.area)
        #self.setLayout(layout)
        #self.pic_holder.resize(500,500)
        #self.pic_holder.setPixmap(pixmap.scaled(self.pic_holder.size(), QtCore.Qt.IgnoreAspectRatio))
        self.show()

    def generate_graph(self):
        if self.details_fetch == 0:

            # Threads to fetch communication and device details
            t = threading.Thread(target=communication_details_fetch.trafficDetailsFetch,args=("sock",))
            t1 = threading.Thread(target=device_details_fetch.fetchDeviceDetails("ieee").fetch_info, args=())
            t.start()
            t1.start()
            #self.progressbar.start()
            #while t.is_alive() or t1.is_alive():
            #      self.progressbar.update()
            t.join()
            t1.join()
            #self.progressbar.stop()
            
            # Report Generation Control and Filters update (Here?)
            self.details_fetch = 1
            
            # Report Creation Threads
            reportThread = threading.Thread(target=report_generator.reportGen(self.report_dir, self.filename).communicationDetailsReport,args=())
            reportThread.start()
            reportThread = threading.Thread(target=report_generator.reportGen(self.report_dir, self.filename).deviceDetailsReport,args=())
            reportThread.start()
        
        # Loding the generated map
        options = self.option+"_"+self.to_ip+"_"+self.from_ip
        self.image_file = os.path.join(self.report_dir, "Report", self.filename+"_"+options+".png")
        if not os.path.exists(self.image_file):
            t1 = threading.Thread(target=plot_lan_network.plotLan, args=(self.filename, self.report_dir, self.option, self.to_ip, self.from_ip))
            t1.start()
            #self.progressbar.start()
            #while t1.is_alive():
            #     self.progressbar.update()
            t1.join()
            #self.progressbar.stop()
            self.load_image()
        else:
            self.load_image()

    def map_select(self):
        self.option = str(self.comboBox.currentText())
        self.to_ip = str(self.comboBox_2.currentText())
        self.from_ip = str(self.comboBox_3.currentText())
        print(self.option, self.to_ip, self.from_ip)
        self.generate_graph()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle('Fusion')
    window = userInterfaceQt()
    window.show()
    sys.exit(app.exec_())