QT -= gui

CONFIG += c++11
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        ../fity.one-api-library/WebAPI.cpp \
        main.cpp

# Default rules for deployment.
#qnx: target.path = /tmp/$${TARGET}/bin
#else: unix:!android: target.path = /opt/$${TARGET}/bin
#!isEmpty(target.path): INSTALLS += target

macx {
    DEFINES += DEBUG_MODE
    INCLUDEPATH += $$PWD/chilkat-9.5.0-macosx/include
    LIBS += -L$$PWD/chilkat-9.5.0-macosx/libStatic -lchilkat_x86_64
}

!exists( $$system_path($$OUT_PWD/api.fity.one)) {
    QMAKE_POST_LINK += $(COPY_DIR) $$system_path($$PWD/api.fity.one) $$system_path($$OUT_PWD)
}

DISTFILES += \
    api.fity.one/api1.fity.one/client1 api1.fity.one.pfx \
    api.fity.one/api1.fity.one/client1.crt \
    api.fity.one/api1.fity.one/private/client1.key \
    api.fity.one/api2.fity.one/client2 api2.fity.one.pfx \
    api.fity.one/api2.fity.one/client2.crt \
    api.fity.one/api2.fity.one/private/client2.key \
    api.fity.one/api3.fity.one/client3 api3.fity.one.pfx \
    api.fity.one/api3.fity.one/client3.crt \
    api.fity.one/api3.fity.one/private/client3.key \
    api.fity.one/api4.fity.one/client4 api4.fity.one.pfx \
    api.fity.one/api4.fity.one/client4.crt \
    api.fity.one/api4.fity.one/private/client4.key \
    api.fity.one/api5.fity.one/client5 api5.fity.one.pfx \
    api.fity.one/api5.fity.one/client5.crt \
    api.fity.one/api5.fity.one/private/client5.key \
    api.fity.one/api6.fity.one/client6 api6.fity.one.pfx \
    api.fity.one/api6.fity.one/client6.crt \
    api.fity.one/api6.fity.one/private/client6.key

HEADERS += \
    ../fity.one-api-library/WebAPI.hpp\
    ../fity.one-api-library/log.h
