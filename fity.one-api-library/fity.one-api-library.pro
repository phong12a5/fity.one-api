#-------------------------------------------------
#
# Project created by Phong.Dang 2019-08-16T22:13:59
#
#-------------------------------------------------

QT       -= gui

TEMPLATE = lib
CONFIG += c++11

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
    WebAPI_global.h \
    log.h\
    auto-genereted-cert.h

CONFIG(debug, debug|release) DEFINES += DEBUG_MODE
CONFIG(debug, debug|release) DEFINES += RELEASE_MODE

CONFIG += f-care-build

f-care-build {
    DEFINES += F_CARE FITYONE_LIBRARY
    TARGET = fcare.fityone
    INCLUDEPATH += $$PWD/chilkat-9.5.0-mingw-5.3.0-32/include
    LIBS += -L$$PWD/chilkat-9.5.0-mingw-5.3.0-32/libs/ -lchilkat-9.5.0 -lws2_32 -lcrypt32 -ldnsapi

    CONFIG(debug, debug|release) target.path =  $$PWD/../release/fity.one-api/fcare/libs/debug
    CONFIG(release, debug|release) target.path =  $$PWD/../release/fity.one-api/fcare/libs/release
    target_headers.path   = $$PWD/../release/fity.one-api/fcare/include
    target_headers.files  = $$PWD/WebAPI.hpp $$PWD/WebAPI_global.h
    INSTALLS              += target_headers target
}

f-system-build {
    DEFINES += F_SYSTEM FITYONE_LIBRARY
    TARGET = fsystem.fityone
    INCLUDEPATH += $$PWD/chilkat-9.5.0-android-cpp/include
    CONFIG(release, debug|release) LIBS += -L$$PWD/chilkat-9.5.0-x86-vc2019/libs/ -lChilkatRel
    CONFIG(debug, debug|release) LIBS += -L$$PWD/chilkat-9.5.0-x86-vc2019/libs/ -lChilkatDbg
    LIBS += crypt32.lib ws2_32.lib dnsapi.lib advapi32.lib

    CONFIG(debug, debug|release) target.path =  $$PWD/../release/fity.one-api/f-system/libs/debug
    CONFIG(release, debug|release) target.path =  $$PWD/../release/fity.one-api/f-system/libs/release
    target_headers.path   = $$PWD/../release/fity.one-api/f-system/include
    target_headers.files  = $$PWD/WebAPI.hpp $$PWD/WebAPI_global.h
    INSTALLS              += target_headers target
}

f-android-build {
    DEFINES += F_ANDROID
    TARGET = fandroid.fityone
    DEFINES += ANDROID_PLATFORM
    INCLUDEPATH += $$PWD/chilkat-9.5.0-android-cpp/include
    LIBS += -L$$PWD/chilkat-9.5.0-android-cpp/libs/$$QT_ARCH/ -lchilkatAndroid

    target_headers.path   = /release/fity.one-api/android/include
    target_headers.files  = $$PWD/WebAPI.hpp $$PWD/WebAPI_global.h
    INSTALLS              += target_headers
}

f-android-webview-build {
    DEFINES += F_ANDROID_WEBVIEW
    TARGET = fandroid-webview.fityone
    DEFINES += ANDROID_PLATFORM
    INCLUDEPATH += $$PWD/chilkat-9.5.0-android-cpp/include
    LIBS += -L$$PWD/chilkat-9.5.0-android-cpp/libs/$$QT_ARCH/ -lchilkatAndroid

    target_headers.path   = /release/fity.one-api/android/include
    target_headers.files  = $$PWD/WebAPI.hpp $$PWD/WebAPI_global.h
    INSTALLS              += target_headers
}

ios-build {

}
