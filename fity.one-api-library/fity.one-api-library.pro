#-------------------------------------------------
#
# Project created by Phong.Dang 2019-08-16T22:13:59
#
#-------------------------------------------------

QT       -= gui

TEMPLATE = lib
CONFIG += f-android-build

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

CONFIG(debug, debug|release) DEFINES += DEBUG_MODE
CONFIG(debug, debug|release) DEFINES += RELEASE_MODE

f-care-build {
    TARGET = fityone-api-
    INCLUDEPATH += $$PWD/chilkat-9.5.0-i686-8.1.0-win32-sjlj/include
    LIBS += -L$$PWD/chilkat-9.5.0-i686-8.1.0-win32-sjlj/libs/ -lchilkat-9.5.0
}

f-system-build {
    TARGET = fityone-api-msvc
    INCLUDEPATH += $$PWD/chilkat-9.5.0-android-cpp/include
    CONFIG(release, debug|release) LIBS += -L$$PWD/chilkat-9.5.0-x86-vc2019/libs/ -lChilkatRel
    CONFIG(debug, debug|release) LIBS += -L$$PWD/chilkat-9.5.0-x86-vc2019/libs/ -lChilkat
}

f-android-build {
    TARGET = fityone-api-android
    DEFINES += ANDROID_PLATFORM
    INCLUDEPATH += $$PWD/chilkat-9.5.0-android-cpp/include
    LIBS += -L$$PWD/chilkat-9.5.0-android-cpp/libs/$$QT_ARCH/ -lchilkatAndroid

    target_headers.path   = /release/fity.one-api/android/include
    target_headers.files  = $$PWD/*.hpp
    INSTALLS              += target_headers
}

ios-build {

}
