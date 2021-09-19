#include <QCoreApplication>
#include <iostream>
#include <QDebug>
#include <CkJsonArray.h>
#include <CkJsonObject.h>
#include <CkStringBuilder.h>
#include <CkRest.h>
#include <CkGlobal.h>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <CkCrypt2.h>
#include <CkCert.h>
#include <CkPrivateKey.h>
#include "../fity.one-api-library/WebAPI.hpp"
#include "../fity.one-api-library/log.h"

using namespace std;
CkGlobal glob;

bool unlockChilkat() {
    bool success_global = glob.UnlockBundle("AUTFRM.CB4082023_Pz2Ry7az86p4");
    if (success_global != true) {
        return false;
    }

    int status = glob.get_UnlockStatus();
    if (status == 2) {
        return true;
    } else {
        return false;
    }
}

static bool readCert(const char * fileName, std::string& content) {
    std::cout << "fileName: " << fileName << std::endl;
    CkCert cert;

    if(!cert.LoadFromFile(fileName)) {
        qDebug() << "Load cert file failed";
        return false;
    }

    content = std::string("-----BEGIN CERTIFICATE-----\n") + cert.getEncoded() + "-----END CERTIFICATE-----";
    std::cout << content << std::endl;
    return true;
}


static bool readPrivateKey(const char * fileName, const char* password, std::string& content) {
    std::cout << "fileName: " << fileName << " password: " << password << std::endl;
    CkPrivateKey privKey;

    if(!privKey.LoadAnyFormatFile(fileName, password)) {
        qDebug() << "Load privatekey file failed";
        return false;
    }

    content = privKey.getPkcs8Pem();
    std::cout << content << std::endl;
    return true;
}


std::string m_encrypt(const char *input, const char *key, const char *iv) {
    if (input == nullptr)
        return "";
    if (key == nullptr)
        return "";
    if (iv == nullptr)
        return "";

    CkCrypt2 crypt;

    crypt.put_CryptAlgorithm("aes");
    crypt.put_CipherMode("cbc");
    crypt.put_KeyLength(256);
    crypt.put_PaddingScheme(0);
    crypt.put_EncodingMode("base64");
    crypt.SetEncodedIV(iv, "ascii");
    crypt.SetEncodedKey(key, "ascii");
    return std::string(crypt.encryptStringENC(input));
}

std::string m_decrypt(const char *input, const char *key, const char *iv) {
    if (input == nullptr)
        return "";
    if (key == nullptr)
        return "";
    if (iv == nullptr)
        return "";

    CkCrypt2 crypt;

    crypt.put_CryptAlgorithm("aes");
    crypt.put_CipherMode("cbc");
    crypt.put_KeyLength(256);
    crypt.put_PaddingScheme(0);
    crypt.put_EncodingMode("base64");
    crypt.SetEncodedIV(iv, "ascii");
    crypt.SetEncodedKey(key, "ascii");
    return std::string(crypt.decryptStringENC(input));
}

static std::string m_md5(const char * input) {
    CkCrypt2 crypt;
    // The desired output is a hexidecimal string:
    crypt.put_EncodingMode("hex");
    // Set the hash algorithm:
    crypt.put_HashAlgorithm("md5");

    return crypt.hashStringENC(input);
}

static bool writeFile(QString fileName, const char * content) {
    QFile file(fileName);
      if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
          return false;

      QTextStream out(&file);
      out << content;
      file.close();
      return true;
}

static void generateEncryptCert() {
    std::string code;
    QString rootFir = "api.fity.one";
    QDir directory(rootFir);
    QStringList apiSubDirs = directory.entryList(QStringList() << "*.fity.one",QDir::Dirs);
    foreach(QString apiSubDir, apiSubDirs) {
        if(apiSubDir.contains(".fity.one")) {
            int index = apiSubDir.indexOf(".fity.one") - 1;
            QString certFile = rootFir + "/" + apiSubDir + "/client" + apiSubDir.at(index) + ".crt";
            std::string cert;
            readCert(certFile.toUtf8().data(),cert);
            std::string encryptedCert = m_encrypt(cert.data(), m_md5("phong.dang").data(),m_md5("pdt").substr(0,16).data());
            code += "static const char * en_cert" + QString(apiSubDir.at(index)).toStdString() + " = \"" + encryptedCert + "\";\n";

            QString privateKeyFile = rootFir + "/" + apiSubDir + "/private/client" + apiSubDir.at(index) + ".key";
            std::string privatekey;
            readPrivateKey(privateKeyFile.toUtf8().data(), QString("client%1").arg(apiSubDir.at(index)).toUtf8().data(), privatekey );
            std::string encryptedPrivatekey = m_encrypt(privatekey.data(), m_md5("dang.phong").data(),m_md5("pdt").substr(0,16).data());
            code += "static const char * en_privatekey" + QString(apiSubDir.at(index)).toStdString() + " = \"" + encryptedPrivatekey + "\";\n";
        }
    }

    writeFile("../fity.one-api-library/auto-genereted-cert.h",code.data());
}

int main(int argc, char *argv[])

{
    QCoreApplication a(argc, argv);

    if (unlockChilkat()){
        qDebug() << "unlockChilkat successfully";
    } else {
        qDebug() << "unlockChilkat Failure";
    }

    WebAPI::getInstance()->initWebAPIs(WebAPI::PLATFORM_CHROME,"129048190238","{\"device_id\":\"1294709742\"}");
    WebAPI::getInstance()->doAction("3209479302745902375");
//    generateEncryptCert();
    return a.exec();
}
