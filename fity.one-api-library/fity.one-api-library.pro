#-------------------------------------------------
#
# Project created by Phong.Dang 2019-08-16T22:13:59
#
#-------------------------------------------------

QT       += testlib
QT       -= gui

TARGET = fityone-api
TEMPLATE = lib
CONFIG += staticlib

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    WebAPI.cpp

HEADERS += \
    WebAPI.hpp \
    log.h\
    auto-genereted-cert.h


# install AutoFarmer API lib
    target.path = /fityone-api/libs/$$ANDROID_TARGET_ARCH
    INSTALLS += target

# Coppy header files to include folder
    target_headers.files  = $$PWD/*.hpp
    target_headers.path   = /fityone-api/include/
    INSTALLS              += target_headers

android {
    DEFINES += ANDROID_PLATFORM
    INCLUDEPATH += $$PWD/chilkat-9.5.0-android-cpp/include
    LIBS += -L$$PWD/chilkat-9.5.0-android-cpp/libs/$$QT_ARCH/ -lchilkatAndroid
}

win32 {

}

macx {
    DISTFILES += MACOS
    INCLUDEPATH += $$PWD/chilkat-9.5.0-macosx/include
    LIBS += -L$$PWD/chilkat-9.5.0-macosx/libStatic -lchilkat_x86_64
}
