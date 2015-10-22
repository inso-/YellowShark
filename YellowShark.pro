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
    paquet.cpp

HEADERS  += mainwindow.h \
    pcap_analyse.h \
    paquet.h

FORMS    += mainwindow.ui

@QT += concurrent@
