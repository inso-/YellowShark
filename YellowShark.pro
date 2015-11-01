#-------------------------------------------------
#
# Project created by QtCreator 2015-10-21T01:02:47
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = YellowShark
TEMPLATE = app
LIBS += -L/opt/local/lib/ -lpcap

SOURCES += main.cpp\
        mainwindow.cpp \
    pcap_analyse.cpp \
    paquet.cpp \
    sendpacketwindow.cpp \
    tools.cpp \
    filterwindow.cpp

HEADERS  += mainwindow.h \
    pcap_analyse.h \
    paquet.h \
    sendpacketwindow.h \
    tools.h \
    filterwindow.h

FORMS    += mainwindow.ui \
    sendpacketwindow.ui \
    filterwindow.ui

@QT += concurrent@
