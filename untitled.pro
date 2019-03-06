TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp

LIBS +=-ldl

QMAKE_CXXFLAGS += -fpermissive
QMAKE_CXXFLAGS += -std=c++11
