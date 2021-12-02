//
// Created by phong.dang on 9/5/2019.
//

#include <iostream>
#include <stdio.h>
#include <mutex>
#include <string>
#include <thread>
#include <future>
#include <sstream>
#include <CkCrypt2.h>
#include <CkJsonObject.h>
#include <CkHttp.h>
#include <CkHttpResponse.h>
#include <CkHttpRequest.h>
#include <CkJsonArray.h>
#include <CkRest.h>
#include <CkBinData.h>
#include <CkGlobal.h>
#include <CkDateTime.h>
#include <CkDtObj.h>
#include <CkRest.h>
#include <CkStream.h>
#include <CkZip.h>
#include <CkSocket.h>
#include "log.h"
#include "WebAPI.hpp"
#include <sys/stat.h>
#include <CkImap.h>
#include <CkEmailBundle.h>
#include <CkEmail.h>
#include <thread>
#include <regex>
#include <CkStringBuilder.h>
#include <CkMessageSet.h>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <CkBinData.h>
#include <CkString.h>
#include <CkRsa.h>
#include <CkPrivateKey.h>
#include <CkCert.h>
#include "auto-genereted-cert.h"

#define KEY_PAIR std::pair<std::string, std::string>
#define KEY_PREFIX "Congaubeo@123"
#define XYZ_DOMAIN "https://api5.autofarmer.net/cgi-bin/autofarmer_api5_1_0.cgi"
#define US_DOMAIN "https://api5.autofarmer.net/cgi-bin/autofarmer_api5_1_0.cgi"

#define DEBUG_LEVEL 0
#define INFO_LEVEL 1
#define ERROR_LEVEL 2

std::string getCurrentTime()
{
    std::string output;
    time_t t;
    struct tm *tmp;
    t = time(nullptr);
    tmp = gmtime(&t);

    char buffer[20];
    snprintf(buffer, 20, "%4d:%02d:%02d:%02d:%02d:%02d", (tmp->tm_year + 1900), (tmp->tm_mon + 1), tmp->tm_mday, tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
    output = std::string(buffer);
    return output;
}

std::string hashKey(const std::string &input, int blockSize)
{
    std::string result;
    if (static_cast<int>(input.length()) >= blockSize && 32 % blockSize == 0)
    {
        for (int i = 0; i < 32 / blockSize; i++)
        {
            if (i + blockSize < static_cast<int>(input.length()))
            {
                result += input.substr(i, blockSize);
            }
            else
            {
                result += input.substr(input.length() - blockSize, blockSize);
            }
        }
    }
    return result;
}

std::string hashIv(const std::string &input, int blockSize)
{
    std::string result;
    if (static_cast<int>(input.length()) >= blockSize && 16 % blockSize == 0)
    {
        for (int i = 0; i < 16 / blockSize; i++)
        {
            if (i + blockSize < static_cast<int>(input.length()))
            {
                result += input.substr(i, blockSize);
            }
            else
            {
                result += input.substr(input.length() - blockSize, blockSize);
            }
        }
    }
    return result;
}

bool getKeyIv(std::string &uid, std::string &key, std::string &iv)
{
    bool retval = false;
    if (uid.length() >= 8)
    {
        for (int i = 0; i < 4; i++)
        {
            if (i + 8 < static_cast<int>(uid.length()))
            {
                key += uid.substr(i, 8);
            }
            else
            {
                key += uid.substr(uid.length() - 8, 8);
            }

            iv += uid.substr(i, 4);
        }
        retval = true;
    }
    else
    {
        LOGE("uid is too short");
    }
    return retval;
}

std::string encrypt(const char *input, const char *key, const char *iv)
{
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

std::string decrypt(const char *input, const char *key, const char *iv)
{
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

std::string md5(std::string input) {
    CkCrypt2 crypt;
    // The desired output is a hexidecimal string:
    crypt.put_EncodingMode("hex");
    // Set the hash algorithm:
    crypt.put_HashAlgorithm("md5");

    return crypt.hashStringENC(input.data());
}

std::string encryptTimestamp(const std::string &timestamp, const std::string &token)
{
    std::string keyFromToken = hashKey(token, 8);
    std::string ivFromToken = hashIv(token, 4);
    return encrypt(timestamp.data(), keyFromToken.data(), ivFromToken.data());
}

std::string decryptTimestamp(const std::string &timestamp, const std::string &token)
{
    std::string keyFromToken = hashKey(token, 8);
    std::string ivFromToken = hashIv(token, 4);
    return decrypt(timestamp.data(), keyFromToken.data(), ivFromToken.data());
}

std::string getKeyFromTimestamp(const std::string &timeStamp)
{
    std::string key = std::string(KEY_PREFIX) + timeStamp + timeStamp;
    return key.substr(0, 32);
}

std::pair<std::string, std::string> getDynamicKey()
{
    std::pair<std::string, std::string> output;
    std::string currTime = getCurrentTime();
    std::string outputKey = std::string(KEY_PREFIX) + currTime + currTime;
    outputKey = outputKey.substr(0, 32);
    output.first = outputKey;
    output.second = currTime;
    return output;
}

std::string toLowerCase(std::string input) {
    std::locale loc;
    std::string output;
    for (std::string::size_type i=0; i<input.length(); ++i) {
        output+= std::tolower(input[i],loc);
    }
    return output;
}

static bool loadJson(CkJsonObject& json, const char * jsonStr) {
    if(jsonStr != nullptr && json.Load(jsonStr) && json.get_Size() > 0) {
        return true;
    } else {
        return false;
    }
}

static void getListContentOfCloudFolder(const char *folderPath, CkJsonObject *output, std::string &token)
{
    LOGD("folderPath: %s", folderPath);
    CkRest rest;
    rest.put_ConnectTimeoutMs(30000);
    bool bTls = true;
    int port = 443;
    bool bAutoReconnect = true;
    if (!rest.Connect("api.dropboxapi.com", port, bTls, bAutoReconnect))
    {
        LOGE("ConnectFailReason: %d", rest.get_ConnectFailReason());
        LOGE("Error: %s", rest.lastErrorText());
        return;
    }

    //  See the Online Tool for Generating JSON Creation Code
    CkJsonObject json;
    json.UpdateString("path", folderPath);
    json.UpdateBool("recursive", false);
    json.UpdateBool("include_media_info", false);
    json.UpdateBool("include_deleted", false);
    json.UpdateBool("include_has_explicit_shared_members", false);
    json.UpdateBool("include_mounted_folders", true);

    //  Add request headers.
    std::string tokenStr = "Bearer " + token;
    rest.AddHeader("Authorization", tokenStr.data());
    rest.AddHeader("Content-Type", "application/json");

    CkStringBuilder sbRequestBody;
    json.EmitSb(sbRequestBody);
    CkStringBuilder sbResponseBody;
    if (!rest.FullRequestSb("POST", "/2/files/list_folder", sbRequestBody, sbResponseBody))
    {
        LOGE("rest.FullRequestSb: %s", rest.lastErrorText());
        return;
    }

    int respStatusCode = rest.get_ResponseStatusCode();
    if (respStatusCode >= 400)
    {
        LOGE("Response Status Code = %d", respStatusCode);
        LOGE("Response Header: %s", rest.responseHeader());
        LOGE("Response Body: %s", sbResponseBody.getAsString());
        return;
    }

    CkJsonObject jsonResponse;
    jsonResponse.LoadSb(sbResponseBody);

    //  See the Online Tool for Generating JSON Parse Code
    int i;
    int count_i;

    jsonResponse.stringOf("cursor");
    jsonResponse.BoolOf("has_more");
    i = 0;
    count_i = jsonResponse.SizeOfArray("entries");
    while (i < count_i)
    {
        jsonResponse.put_I(i);
        const char *Tag = jsonResponse.stringOf("entries[i].\".tag\"");
        const char *name = jsonResponse.stringOf("entries[i].name");
        if (output->IndexOf(name) == -1)
        {
            output->UpdateString(name, Tag);
        }
        i = i + 1;
    }
}

static void getJsonCommon(CkJsonObject &object, std::vector<std::string> &keyList, std::vector<std::string> &valueList, int fieldNumber)
{
    srand(time(nullptr));
    if (keyList.size() == valueList.size() &&
        fieldNumber <= static_cast<int>(keyList.size()))
    {

        for (int i = 0; i < fieldNumber; i++)
        {
            int randIndex = i + rand() % (fieldNumber - i);
            std::string key = keyList[randIndex];
            keyList[randIndex] = keyList[i];
            keyList[i] = key;

            randIndex = i + rand() % (fieldNumber - i);
            std::string value = valueList[randIndex];
            valueList[randIndex] = valueList[i];
            valueList[i] = value;

            KEY_PAIR keyPair = getDynamicKey();
            static std::string tmpiv = "phongdeptrai_phongvandeptrai_01071994";
            object.UpdateString(key.data(), encrypt(value.data(), keyPair.first.data(),
                                                    tmpiv.substr(2, 16).data())
                                                .data());
        }
    }
}

static bool getCert(CkCert& cert, WebAPI::E_SUPPORTED_PLATFORM platform) {

    std::string en_cert, en_privatekey, keyPass;

    switch (platform) {
    case WebAPI::PLATFORM_F_CARE:
        en_cert = en_cert1;
        en_privatekey = en_privatekey1;
        keyPass = "client1";
        break;
    case WebAPI::PLATFORM_F_SYSTEM:
        en_cert = en_cert2;
        en_privatekey = en_privatekey2;
        keyPass = "client2";
        break;
    case WebAPI::PLATFORM_F_ANDROID:
        en_cert = en_cert3;
        en_privatekey = en_privatekey3;
        keyPass = "client3";
        break;
    case WebAPI::PLATFORM_F_ANDROID_WEBVIEW:
        en_cert = en_cert4;
        en_privatekey = en_privatekey4;
        keyPass = "client4";
        break;
    case WebAPI::PLATFORM_F_IOS:
        en_cert = en_cert5;
        en_privatekey = en_privatekey5;
        keyPass = "client5";
        break;
    case WebAPI::PLATFORM_F_IOS_WEBVIEW:
        en_cert = en_cert6;
        en_privatekey = en_privatekey6;
        keyPass = "client6";
        break;
    default:
        return false;
    }

    if (!cert.LoadPem(decrypt(en_cert.data(), md5("phong.dang").data(), md5("pdt").substr(0,16).data()).data())) {
        LOGE("Load cert error: %s",cert.lastErrorText());
        return false;
    }
//    LOGD("privKey: %s",cert.getEncoded());

    CkPrivateKey privKey;
    if (!privKey.LoadEncryptedPem(decrypt(en_privatekey.data(),md5("dang.phong").data(),md5("pdt").substr(0,16).data()).data(),keyPass.data())) {
        LOGE("load key error: %s",privKey.lastErrorText());
        return false;
    };
//    LOGD("privKey: %s",privKey.getPkcs8Pem());
    // Associate the private key with the cert.
    if (!cert.SetPrivateKey(privKey)) {
        LOGE("SetPrivateKey error: %s",cert.lastErrorText());
        return false;
    }

    return true;
}

std::string deviceInfo2CKJson(const WebAPI::E_SUPPORTED_PLATFORM platform, const DEVICE_INFO& device_info) {
    CkJsonObject json;
    json.UpdateString("device_id",device_info.device_id);
    json.UpdateString("app_version_name",device_info.app_version_name);

    switch (platform) {
    case WebAPI::PLATFORM_F_CARE:
        json.UpdateString("system","f_care");
        break;
    case WebAPI::PLATFORM_F_SYSTEM:
        json.UpdateString("system","f_system");
        break;
    case WebAPI::PLATFORM_F_ANDROID:
        json.UpdateString("system","f_android");
        break;
    case WebAPI::PLATFORM_F_ANDROID_WEBVIEW:
        json.UpdateString("system","f_android_webview");
        break;
    case WebAPI::PLATFORM_F_IOS:
        json.UpdateString("system","f_ios");
        break;
    case WebAPI::PLATFORM_F_IOS_WEBVIEW:
        json.UpdateString("system","f_ios_webview");
        break;
    default:
        json.UpdateString("system","unknown");
        break;
    }
    return std::string(json.emit());
}

WebAPI::WebAPI()
{
#if defined (F_CARE)
    m_system_type = WebAPI::PLATFORM_F_CARE;
#elif defined (F_SYSTEM)
    m_system_type = WebAPI::PLATFORM_F_SYSTEM;
#elif defined (F_ANDROID)
    m_system_type = WebAPI::PLATFORM_F_ANDROID;
#elif defined (F_ANDROID_WEBVIEW)
    m_system_type = WebAPI::PLATFORM_F_ANDROID_WEBVIEW;
#elif defined (F_IOS)
    m_system_type = WebAPI::PLATFORM_F_IOS;
#elif defined (IOS_WEBVIEW)
    m_system_type = WebAPI::PLATFORM_F_IOS_WEBVIEW;
#else
    m_system_type = WebAPI::PLATFORM_UNKNOWN;
#endif
    m_initState = false;
    m_token = "";

    m_unlockState = unlockChilkat();
    m_dropBoxToken = "";
    m_existedPackagedList.clear();
    LOGD("**************************** Created WebAPI instance --- Phong Dep Trai! ****************************");
}

WebAPI *WebAPI::getInstance()
{
    static WebAPI *instance = nullptr;
    if (instance == nullptr)
    {
        instance = new WebAPI();
    }
    return instance;
}

std::string WebAPI::version() {
    return "0.0.1";
}

/* Private */
bool WebAPI::initState() const
{
    return m_initState;
}

void WebAPI::setInitState(bool state)
{
    LOGD("state: %d", state);
    m_initState = state;
}

bool WebAPI::downloadFile(std::string &url, const std::string &savedPath)
{
    CkHttp http;
    http.put_ConnectTimeout(30);
    http.put_ReadTimeout(30);

    bool retVal = http.Download(url.c_str(), savedPath.c_str());
    if (!retVal)
    {
        LOGE("Error: %s", http.lastErrorText());
    }
    return retVal;
}

std::string WebAPI::getFolderContent(const char *folderPath)
{
    std::string result;
    CkJsonObject ckJsonObject;
    std::string token;
    if (!getDropboxToken(token))
    {
        LOGE("Get dropbox token failed");
    }
    else
    {
        getListContentOfCloudFolder(folderPath, &ckJsonObject, token);
        if (ckJsonObject.emit() != nullptr)
        {
            result = std::string(ckJsonObject.emit());
        }
    }
    return result;
}

const char *WebAPI::getKey()
{
    return "Congaubeo@123456Congaubeo@123456";
}

const char *WebAPI::getIv()
{
    return "Congaubeo@123560";
}

bool WebAPI::unlockChilkat()
{
    LOGD("unlockChilkat");
    CkGlobal glob;
    bool success_global = glob.UnlockBundle("AUTFRM.CB4082023_Pz2Ry7az86p4");
    if (!success_global)
    {
        LOGD("Error: %s", glob.lastErrorText());
        return false;
    }

    int status = glob.get_UnlockStatus();
    if (status == 2)
    {
        LOGD("Unlocked using purchased unlock code.");
    }
    else
    {
        LOGD("Unlocked in trial mode.");
    }
    return true;
}

bool WebAPI::getDropboxToken(std::string &dropboxToken)
{
    bool result = false;
    if (!m_dropBoxToken.empty())
    {
        dropboxToken = m_dropBoxToken;
        result = true;
    }
    return result;
}

std::string WebAPI::getDomain()
{
    switch (m_system_type) {
    case WebAPI::PLATFORM_F_CARE:
        return "https://api1.fity.one/cgi-bin/fity-one.cgi?system=f_care";
    case WebAPI::PLATFORM_F_SYSTEM:
        return "https://api2.fity.one/cgi-bin/fity-one.cgi?system=f_system";
    case WebAPI::PLATFORM_F_ANDROID:
        return "https://api3.fity.one/cgi-bin/fity-one.cgi?system=f_android";
    case WebAPI::PLATFORM_F_ANDROID_WEBVIEW:
        return "https://api4.fity.one/cgi-bin/fity-one.cgi?system=f_android_webview";
    case WebAPI::PLATFORM_F_IOS:
        return "https://api5.fity.one/cgi-bin/fity-one.cgi?system=f_ios";
    case WebAPI::PLATFORM_F_IOS_WEBVIEW:
        return "https://api6.fity.one/cgi-bin/fity-one.cgi?system=f_ios_webview";
    default:
        return std::string();
    }
}

std::string WebAPI::getUrlByAPI(std::string api)
{
    return getDomain() + std::string("&api=") + api + std::string("&token=") + m_token;
}

bool WebAPI::encryptCloneInfo(std::string &cloneInfo)
{
    bool retVal = false;
    CkJsonObject cloneInfoObj;
    cloneInfoObj.put_Utf8(true);
    if (loadJson(cloneInfoObj,cloneInfo.data())) {
        if (cloneInfoObj.HasMember("uid")) {
            std::string uid = cloneInfoObj.stringOf("uid");
            std::string key, iv;
            getKeyIv(uid, key, iv);
            LOGD("uid: %s -- key: %s -- iv: %s", uid.data(), key.data(), iv.data());

            if (key.length() == 32 && iv.length() == 16) {
                CkJsonObject mzz;
                if (cloneInfoObj.HasMember("password")) {
                    std::string password = cloneInfoObj.stringOf("password");
                    std::string enPassword = encrypt(password.data(), key.data(), iv.data());
                    cloneInfoObj.UpdateString("password", enPassword.data());
                    mzz.UpdateBool("p",true);
                }

                if (cloneInfoObj.HasMember("secretkey")) {
                    std::string scretkey = cloneInfoObj.stringOf("secretkey");
                    std::string enSecretkey = encrypt(scretkey.data(), key.data(), iv.data());
                    cloneInfoObj.UpdateString("secretkey", enSecretkey.data());
                    mzz.UpdateBool("s",true);
                }

                cloneInfoObj.Delete("mzz");
                cloneInfoObj.AddObjectCopyAt(-1,"mzz", mzz);
                cloneInfo = std::string(cloneInfoObj.emit());
                retVal = true;
            } else  {
                LOGE("invalid key: %s or iv: %s", key.data(), iv.data());
            }
        } else {
            LOGE("No uid!");
        }

        cloneInfo = std::string(cloneInfoObj.emit());
    } else  {
        LOGE("Parse cloneInfo failed");
    }
    return retVal;
}

bool WebAPI::decryptCloneInfo(std::string &cloneInfo)
{
    bool retVal = false;
    CkJsonObject cloneInfoObj;
    cloneInfoObj.put_Utf8(true);
    if (loadJson(cloneInfoObj,cloneInfo.data())) {
        if (cloneInfoObj.HasMember("uid")) {
            std::string uid = cloneInfoObj.stringOf("uid");
            std::string key, iv;
            getKeyIv(uid, key, iv);
            LOGD("uid: %s -- key: %s -- iv: %s", uid.data(), key.data(), iv.data());

            if (key.length() == 32 && iv.length() == 16) {
                CkJsonObject* mzz = cloneInfoObj.ObjectOf("mzz");

                if (cloneInfoObj.HasMember("password") && mzz && mzz->BoolOf("p"))
                {
                    const char *enPassword = cloneInfoObj.stringOf("password");
                    std::string password = decrypt(enPassword, key.data(), iv.data());
                    cloneInfoObj.UpdateString("password", password.data());
                }

                if (cloneInfoObj.HasMember("secretkey") && mzz && mzz->BoolOf("s"))
                {
                    const char *enScretkey = cloneInfoObj.stringOf("secretkey");
                    std::string secretkey = decrypt(enScretkey, key.data(), iv.data());
                    cloneInfoObj.UpdateString("secretkey", secretkey.data());
                }

                cloneInfo = std::string(cloneInfoObj.emit());
                retVal = true;
            } else  {
                LOGE("invalid key: %s or iv: %s", key.data(), iv.data());
            }
        } else {
            LOGE("No uid!");
        }
    } else {
        LOGE("Parse cloneInfo failed");
    }
    return retVal;
}

bool WebAPI::initWebAPIs(const char *token, DEVICE_INFO& deviceInfo)
{
    LOGD("initWebAPIs");
    CkJsonObject deviceJson;
    if(deviceInfo.device_id == nullptr || std::string(deviceInfo.device_id).empty()) {
        LOGE("Invalid device_id!");
    } else if (token == nullptr || std::string(token).empty()) {
        LOGE("Invalid token");
    }
    else
    {
        setInitState(true);
        m_deviceInfo = deviceInfo;
        m_token = token;
        LOGD("m_token: %s", m_token.data());
        LOGD("m_deviceInfo: %s", deviceInfo2CKJson(m_system_type, m_deviceInfo).data());
    }

    LOGD("initWebAPIs: %s", (initState() ? "successful" : "failure"));
    return initState();
}

std::string WebAPI::token() const
{
    return m_token;
}

DEVICE_INFO WebAPI::deviceInfo() const
{
    return m_deviceInfo;
}

void WebAPI::pLog(int level, const char *TAG, const char *fmt, ...) const
{

    char msg[10000];
    va_list arg_ptr;
    va_start(arg_ptr, fmt);
    vsnprintf(msg, sizeof msg, fmt, arg_ptr);
    va_end(arg_ptr);

    switch (level)
    {
    case DEBUG_LEVEL:
#ifdef DEBUG_MODE
        LOGD("%s: %s", TAG, msg);
#endif
        pushLog2Server("DEBUG/", TAG, msg);
        break;
    case INFO_LEVEL:
#ifdef DEBUG_MODE
        LOGI("%s: %s", TAG, msg);
#endif
        pushLog2Server("INFO/", TAG, msg);
        break;
    case ERROR_LEVEL:
#ifdef DEBUG_MODE
        LOGE("%s: %s", TAG, msg);
#endif
        pushLog2Server("DEBUG/", TAG, msg);
        break;
    default:
        break;
    }
}

void WebAPI::pushLog2Server(const char *level, const char *TAG, const char *msg)
{
    std::ignore = level;
    std::ignore = TAG;
    std::ignore = msg;
}

// Autofarmer APIs
std::string WebAPI::upsertDevice(const char * extraDeviceInfo) {
    LOGD("");
    CkJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "Upsert");

    if (sendRequest( __FUNCTION__ , bodyData, response, "config", extraDeviceInfo)) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::updateDeviceInfo(const char * extraDeviceInfo) {
    LOGD("");
    CkJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "UpdateDeviceInfo");

    if (sendRequest( __FUNCTION__ , bodyData, response, "config", extraDeviceInfo)) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getConfig()
{
    LOGD("");
    CkJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetConfig");

    if (sendRequest( __FUNCTION__ ,bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
            }

            if (server_data->HasMember("version")) {
                retVal.UpdateString("version", server_data->stringOf("version"));
            }

            if (server_data->HasMember("new_token")) {
                retVal.UpdateString("new_token", server_data->stringOf("new_token"));
            }

            if (server_data->HasMember("data")) {
                const char *data = server_data->stringOf("data");
                CkJsonObject configJson;
                if (loadJson(configJson, data)) {
                    retVal.AddObjectCopyAt(-1, "data", configJson);
                    retVal.UpdateBool("success", true);

                    if (configJson.HasMember("dropboxaccesstoken")) {
                        m_dropBoxToken = std::string(configJson.stringOf("dropboxaccesstoken"));
                    } else {
                        retVal.UpdateString("warning_message",
                                            "Dropboxaccesstoken field is not existed!");
                    }
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getClone()
{
    LOGD("");
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetClone");

    if (sendRequest( __FUNCTION__, bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)  {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data()))
                {
                    retVal.AddObjectCopyAt(-1, "data", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getCloneInfo(const char *clone_info)
{
    LOGD("clone_info: %s", clone_info);
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    std::string cloneInfoStr = std::string(clone_info);
    encryptCloneInfo(cloneInfoStr);
    LOGD("cloneInfoStr: %s", cloneInfoStr.data());

    CkString str;
    str.put_Utf8(true);
    str.setString(cloneInfoStr.data());
    str.base64Encode("utf-8");

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetCloneInfo");
    bodyData.UpdateString("clone_info", str.getString());

    if (sendRequest(__FUNCTION__ , bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data())) {
                    retVal.AddObjectCopyAt(-1, "data", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getStoredClones()
{
    LOGD("");
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetStoredClones");

    if (sendRequest(__FUNCTION__ , bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                CkJsonArray storedClones;
                storedClones.put_Utf8(true);
                if (storedClones.Load(data.data())) {
                    retVal.AddArrayCopyAt(-1, "data", storedClones);
                } else {
                    LOGE("Load data failed");
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::updateClone(const char * action, const char *cloneJsonPath)
{
    LOGD("action: %s -- cloneJsonPath: %s",action, cloneJsonPath);
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    std::string cloneInfoStr = std::string(cloneJsonPath);
    encryptCloneInfo(cloneInfoStr);
    LOGD("cloneInfoStr: %s", cloneInfoStr.data());

    CkString str;
    str.put_Utf8(true);
    str.setString(cloneInfoStr.data());
    str.base64Encode("utf-8");

    CkJsonObject bodyData, response, cloneInfo;
    bodyData.UpdateString("action", action);
    bodyData.UpdateString("clone_info", str.getString());

    if (sendRequest( __FUNCTION__ , bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {

            if (server_data->HasMember("code")) {
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data")) {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data())) {
                    retVal.AddObjectCopyAt(-1, "data", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::doAction(const char *clone_id)
{
    LOGD("clone_id: %s", clone_id);
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("clone_id", clone_id);

    if (sendRequest( __FUNCTION__ , bodyData, response, "get-do-actions")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("data")) {
                CkJsonArray actionsArr;
                actionsArr.put_Utf8(true);
                if(actionsArr.Load(server_data->stringOf("data")))
                retVal.AddArrayCopyAt(-1, "data", actionsArr);
            }

            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::doResult(const char *clone_id, const char *dataJsonPath)
{
    LOGD("clone_id: %s -- dataJsonPath: %s", clone_id, dataJsonPath);
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response, actionObj;
    bodyData.UpdateString("clone_id", clone_id);
    if (loadJson(actionObj,dataJsonPath))
        bodyData.AddObjectCopyAt(-1, "data", actionObj);

    if (sendRequest( __FUNCTION__, bodyData, response, "do-result")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200 || server_data->IntOf("code") == 400 || server_data->IntOf("code") == 401);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    LOGD("result: %s",retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getJasmineDefinitions()
{
    LOGD("");
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetJasmine");

    if (sendRequest( __FUNCTION__, bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("data")) {
                CkJsonArray definitionArr;
                definitionArr.put_Utf8(true);
                if(definitionArr.Load(server_data->stringOf("data"))) {
                    retVal.UpdateBool("success", true);
                    retVal.AddArrayCopyAt(-1, "data", definitionArr);
                }
            }
        }
    }
    LOGD("result: %s",retVal.emit());
    return retVal.emit();
}

std::string WebAPI::submitActiveClones(const char *activeClones)
{
    LOGD("activeClones: %s", activeClones);
    CkJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    CkJsonArray activeCloneArr;
    if (activeCloneArr.Load(activeClones)) bodyData.AddArrayCopyAt(-1, "clone_ids", activeCloneArr);
    bodyData.UpdateString("action", "SubmitActiveClones");

    if (sendRequest( __FUNCTION__, bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {
            if (server_data->HasMember("code")) {
                retVal.UpdateInt("code", server_data->IntOf("code"));
                retVal.UpdateBool("success", server_data->IntOf("code") == 200 || server_data->IntOf("code") == 400);
            }

            if (server_data->HasMember("message")) {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getHotmail()
{
    LOGD("");
    CkJsonObject retVal;
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetHotMail");

    if (sendRequest( __FUNCTION__, bodyData, response, "config"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("code") && server_data->IntOf("code") == 200)
            {
                retVal.UpdateBool("success", true);
            }

            if (server_data->HasMember("data"))
            {
                CkJsonObject emailObj;
                emailObj.put_Utf8(true);
                if (loadJson(emailObj,server_data->stringOf("data")))
                {
                    retVal.AddObjectCopyAt(-1, "data", emailObj);
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getCodeFromImap(const char * imapServer, int port, const char * mailBox, const char * fromName, const char* toEmail, const char * login_email, const char * login_password) const {
    LOGD("email: %s -- passwd: %s", login_email, login_password);
    CkImap imap;

    // Connect to they Yahoo! IMAP server.
    //outlook: 993
    imap.put_Port(port);
    imap.put_Ssl(true);
    //outlook: "outlook.office365.com"
    bool success = imap.Connect(imapServer);
    if (!success)
    {
        LOGE("imap.Connect: %s", imap.lastErrorText());
        return "";
    }
    // Send the non-standard ID command...
    imap.sendRawCommand("ID (\"GUID\" \"1\")");
    if (!imap.get_LastMethodSuccess())
    {
        LOGE("imap.sendRawCommand: %s", imap.lastErrorText());
        return "";
    }

    // Login
    success = imap.Login(login_email, login_password);
    if (!success) {
        LOGE("imap.Login: %s", imap.lastErrorText());
        return "";
    }

    LOGD("Login Success!");

    std::string code;

    //outlook: "Inbox"
    success = imap.SelectMailbox(mailBox);
    if (!success) {
        LOGE("imap.SelectMailbox: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("SelectMailbox success!");
    }

    // We can choose to fetch UIDs or sequence numbers.
    bool fetchUids = true;
    // Get the message IDs of all the emails in the mailbox
    CkMessageSet *messageSet = imap.Search("ALL", fetchUids);
    if (!imap.get_LastMethodSuccess()) {
        LOGE("imap.Search: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("Search ALL mail box success!");
    }

    // Fetch the emails into a bundle object:
    CkEmailBundle *bundle = imap.FetchBundle(*messageSet);
    if (!imap.get_LastMethodSuccess()) {
        delete messageSet;
        messageSet = nullptr;
        LOGE("imap.FetchBundle: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("FetchBundle success!");
    }

    // Loop over the bundle and display the FROM and SUBJECT of each.
    int i = 0;
    int numEmails = bundle->get_MessageCount();
    while (i < numEmails) {
        CkEmail *ckEmail = bundle->GetEmail(i);
        LOGD("email from -> %s", ckEmail->ck_from());
        LOGD("email to -> %s", ckEmail->getToAddr(0));
        LOGD("email subject -> %s", ckEmail->subject());

        if (std::string(ckEmail->ck_from()).find(fromName) != std::string::npos ||
            std::string(ckEmail->getToAddr(0)).find(toEmail) != std::string::npos) {
            LOGD("body: %s", ckEmail->subject());
            std::cmatch veriCodeMatchValue;
            if (regex_search(ckEmail->subject(), veriCodeMatchValue, std::regex("\\d{5,7}"))) {
                code = veriCodeMatchValue[0];
                //bool SetFlag(int msgId, bool bUid, const char *flagName, int value);
                // delete email
                imap.SetFlag(ckEmail->GetImapUid(), true, "Deleted", 1);
            }
        }
        delete ckEmail;
        i = i + 1;
    }

    // Expunge and close the mailbox.
    success = imap.ExpungeAndClose();

    delete messageSet;
    delete bundle;

    // Disconnect from the IMAP server.
    success = imap.Disconnect();
    LOGD("code: %s", code.data());
    return code;
}


bool WebAPI::sendRequest(const char * caller, CkJsonObject &bodyData, CkJsonObject &response, const char *api, const char * extraDeviceInfo)
{
    LOGD("%s -- url: %s", caller, getUrlByAPI(api).data());
    LOGD("%s -- data: %s", caller, bodyData.emit());
    std::ignore = caller;
    bool success = false;
    if (initState())
    {
        CkJsonObject deviceInfo;
        if (loadJson(deviceInfo,deviceInfo2CKJson(m_system_type, m_deviceInfo).data())) {
            if(extraDeviceInfo) {
                LOGD("extraDeviceInfo: %s", extraDeviceInfo);
                CkJsonObject extraDeviceInfoObj;
                if(loadJson(extraDeviceInfoObj,extraDeviceInfo)) {
                    for (int i = 0; i < extraDeviceInfoObj.get_Size(); ++i) {
                        const char * key = extraDeviceInfoObj.nameAt(i);
                        int type = extraDeviceInfoObj.TypeAt(i);
                        switch (type) {
                            case 1:
                                deviceInfo.UpdateString(key, extraDeviceInfoObj.stringOf(key));
                                break;
                            case 2:
                                deviceInfo.UpdateInt(key, extraDeviceInfoObj.IntOf(key));
                                break;
                            case 5:
                                deviceInfo.UpdateBool(key, extraDeviceInfoObj.BoolOf(key));
                                break;
                            default:
                                break;
                        }
                    }
                }
                LOGD("deviceInfo: %s", deviceInfo.emit());
            }
            bodyData.AddObjectCopyAt(-1, "device_info", deviceInfo);
        }


        bodyData.UpdateString("token", m_token.data());

        KEY_PAIR keyPair = getDynamicKey();
        std::string enData = encrypt(bodyData.emit(), keyPair.first.data(), WebAPI::getIv());
        std::string enClientTimestamp = encryptTimestamp(keyPair.second, m_token);

        CkJsonObject jsonReqBody;
        getJsonCommon(jsonReqBody, m_listKey, m_listValue, 100);
        jsonReqBody.UpdateString("data", enData.data());
        jsonReqBody.UpdateString("client_timestamp", enClientTimestamp.data());

        CkHttp http;
        http.put_ConnectTimeout(30);
        http.put_ReadTimeout(30);
        http.SetRequestHeader("Content-Type", "application/json");
        http.SetRequestHeader("mobile-secret-key", md5(m_token).data());

        CkCert cert;
        if(!getCert(cert, m_system_type)) {
            LOGE("GetCert failed!");
            response.UpdateString("error", "GetCert failed!");
        } else if(!http.SetSslClientCert(cert)) {
            LOGE("SetSslClientCert error: %s", http.lastErrorText());
            response.UpdateString("error", "SetSslClientCert error!");
        } else {
            LOGD("Apply certificate successfully!");
            CkHttpResponse *resp = http.PostJson(getUrlByAPI(api).data(), jsonReqBody.emit());

            if (!http.get_LastMethodSuccess()) {
                response.UpdateString("error", http.lastErrorText());
            } else {
                if (resp->bodyStr()) {
                    LOGD("BodyStr: %s", resp->bodyStr());
                    CkJsonObject jsonResponse;
                    jsonResponse.put_Utf8(true);
                    if (loadJson(jsonResponse, resp->bodyStr())) {
                        jsonResponse.put_EmitCompact(false);
                        if (jsonResponse.HasMember("data")) {
                            if (jsonResponse.HasMember("server_timestamp")) {
                                std::string serverTimeStamp = std::string(
                                        jsonResponse.stringOf("server_timestamp"));
                                serverTimeStamp = decryptTimestamp(serverTimeStamp, m_token);

                                std::string key = getKeyFromTimestamp(serverTimeStamp);
                                std::string data = decrypt(jsonResponse.stringOf("data"),
                                                           key.data(), WebAPI::getIv());

                                LOGD("decoded data: %s", data.data());
                                CkJsonObject responseData;
                                responseData.put_Utf8(true);

                                if (loadJson(responseData, data.data())) {
                                    if (responseData.HasMember("data")) {
                                        CkJsonObject server_data;
                                        server_data.put_Utf8(true);
                                        if (loadJson(server_data, responseData.stringOf("data"))) {
                                            if (server_data.HasMember("data")) {
                                                CkBinData ckstr;
                                                ckstr.put_Utf8(true);
                                                ckstr.AppendEncoded(server_data.stringOf("data"),
                                                                    "base64");
                                                server_data.UpdateString("data",
                                                                         ckstr.getString("utf-8"));
                                            }
                                            response.put_Utf8(true);
                                            response.AddObjectCopyAt(-1, "data", server_data);
                                        }
                                    }

                                    if (responseData.HasMember("cgi_message")) {
                                        response.UpdateString("cgi_message",
                                                              responseData.stringOf("cgi_message"));
                                    }

                                    if (responseData.HasMember("response_code")) {
                                        response.UpdateInt("response_code",
                                                           responseData.IntOf("response_code"));
                                    }

                                    if (responseData.HasMember("success")) {
                                        response.UpdateBool("success",
                                                            responseData.BoolOf("success"));
                                    }
                                    success = true;
                                }
                            } else {
                                response.UpdateString("error_message", "could not obtain server_timestamp");
                            }
                        } else {
                            response.UpdateString("error", "\"data\" field don't existed!");
                        }
                    } else {
                        response.UpdateString("error", "Could not load response -> json");
                        response.UpdateString("response", resp->bodyStr());
                    }
                } else {
                    response.UpdateString("error", "response: NULL");
                }
            }
            delete resp;
        }
    } else {
        response.UpdateString("error", "Init WebAPI failed");
    }
    LOGD("response: %s", response.emit());
    return success;
}

// Dropbox APIs

bool WebAPI::downloadFileFromDropbox(const char *pathFile, const char *savePath)
{
    LOGD("pathFile: %s -- savePath: %s", pathFile, savePath);
    CkRest rest;
    rest.put_IdleTimeoutMs(120000);

    //  Connect to Dropbox
    if (!rest.Connect("content.dropboxapi.com", 443, true, true))
    {
        LOGD("Connect error: %s", rest.lastErrorText());
        return false;
    }

    std::string token;
    if (!getDropboxToken(token))
    {
        LOGE("Get dropbox token failed");
        return false;
    }
    //  Add request headers.
    std::string tokenStr = "Bearer " + token;
    rest.AddHeader("Authorization", tokenStr.data());

    CkJsonObject json;
    json.AppendString("path", pathFile);
    rest.AddHeader("Dropbox-API-Arg", json.emit());

    CkStream fileStream;
    fileStream.put_SinkFile(savePath);

    int expectedStatus = 200;
    rest.SetResponseBodyStream(expectedStatus, true, fileStream);

    rest.fullRequestNoBody("POST", "/2/files/download");
    if (!rest.get_LastMethodSuccess())
    {
        LOGD("responseStr error: %s", rest.lastErrorText());
        return false;
    }
    //  When successful, Dropbox responds with a 200 response code.
    if (rest.get_ResponseStatusCode() != 200)
    {
        //  Examine the request/response to see what happened.
        LOGE("response status code = %d", rest.get_ResponseStatusCode());
        LOGE("response status text = %s", rest.responseStatusText());
        LOGE("response header: %s", rest.responseHeader());
        LOGE("response body (if any): %s", rest.readRespBodyString());
        LOGE("LastRequestStartLine: %s", rest.lastRequestStartLine());
        LOGE("LastRequestHeader: %s", rest.lastRequestHeader());
        LOGE("lastErrorText: %s", rest.lastErrorText());
        return false;
    }
    LOGD("Download %s successful", pathFile);
    return true;
}

std::string WebAPI::getFacebookCodeFromCGBDomainMail(const char * email, const char * mailbox) const {
    LOGD("email: %s", email);
//    return getCodeFromImap("imap.yandex.com", 993, "Spam", "Facebook", email, "admin@bobolala.xyz", "ecstipxneiopwyvx");

    LOGD("email: %s", email);
    CkImap imap;

    // Connect to they Yahoo! IMAP server.
    //outlook: 993
    imap.put_Port(993);
    imap.put_Ssl(true);
    //outlook: "outlook.office365.com"
    bool success = imap.Connect("imap.yandex.com");
    if (!success)
    {
        LOGE("imap.Connect: %s", imap.lastErrorText());
        return "";
    }
    // Send the non-standard ID command...
    imap.sendRawCommand("ID (\"GUID\" \"1\")");
    if (!imap.get_LastMethodSuccess())
    {
        LOGE("imap.sendRawCommand: %s", imap.lastErrorText());
        return "";
    }

    // Login
    success = imap.Login("admin@bobolala.xyz", "ecstipxneiopwyvx");
    if (!success) {
        LOGE("imap.Login: %s", imap.lastErrorText());
        return "";
    }

    LOGD("Login Success!");

    std::string code;

    //outlook: "Inbox"
    success = imap.SelectMailbox(mailbox);
    if (!success) {
        LOGE("imap.SelectMailbox: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("SelectMailbox success!");
    }

    // We can choose to fetch UIDs or sequence numbers.
    bool fetchUids = true;
    // Get the message IDs of all the emails in the mailbox
    CkMessageSet *messageSet = imap.Search("ALL", fetchUids);
    if (!imap.get_LastMethodSuccess()) {
        LOGE("imap.Search: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("Search ALL mail box success!");
    }

    // Fetch the emails into a bundle object:
    CkEmailBundle *bundle = imap.FetchBundle(*messageSet);
    if (!imap.get_LastMethodSuccess()) {
        delete messageSet;
        messageSet = nullptr;
        LOGE("imap.FetchBundle: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("FetchBundle success!");
    }

    // Loop over the bundle and display the FROM and SUBJECT of each.
    int i = 0;
    int numEmails = bundle->get_MessageCount();
    while (i < numEmails) {
        CkEmail *ckEmail = bundle->GetEmail(i);
        LOGD("email from -> %s", ckEmail->ck_from());
        LOGD("email to -> %s", ckEmail->getToAddr(0));
        LOGD("email subject -> %s", ckEmail->subject());

        if (std::string(ckEmail->ck_from()).find("Facebook") != std::string::npos ||
            std::string(ckEmail->getToAddr(0)).find(email) != std::string::npos) {
            LOGD("body: %s", ckEmail->subject());
            std::cmatch veriCodeMatchValue;
            if (regex_search(ckEmail->subject(), veriCodeMatchValue, std::regex("\\d{5,7}"))) {
                code = veriCodeMatchValue[0];
                //bool SetFlag(int msgId, bool bUid, const char *flagName, int value);
                // delete email
                imap.SetFlag(ckEmail->GetImapUid(), true, "Deleted", 1);
            }
        }
        delete ckEmail;
        i = i + 1;
    }

    // Expunge and close the mailbox.
    success = imap.ExpungeAndClose();

    delete messageSet;
    delete bundle;

    // Disconnect from the IMAP server.
    success = imap.Disconnect();
    LOGD("code: %s", code.data());
    return code;
}

std::string WebAPI::getTiktokCodeFromCGBDomainMail(const char * email) const {
    LOGD("email: %s", email);
    return getCodeFromImap("imap.yandex.com", 993, "Inbox", "TikTok", email, "admin@bobolala.xyz", "ecstipxneiopwyvx");
}

std::string WebAPI::getFacebookCodeFromHotmail(const char * email, const char * password, const char * mailbox) const {
    LOGD("email: %s -- passwd: %s", email, password);
    CkImap imap;

    // Connect to they Yahoo! IMAP server.
    //outlook: 993
    imap.put_Port(993);
    imap.put_Ssl(true);
    //outlook: "outlook.office365.com"
    bool success = imap.Connect("outlook.office365.com");
    if (!success)
    {
        LOGE("imap.Connect: %s", imap.lastErrorText());
        return "";
    }
    // Send the non-standard ID command...
    imap.sendRawCommand("ID (\"GUID\" \"1\")");
    if (!imap.get_LastMethodSuccess())
    {
        LOGE("imap.sendRawCommand: %s", imap.lastErrorText());
        return "";
    }

    // Login
    success = imap.Login(email, password);
    if (!success) {
        LOGE("imap.Login: %s", imap.lastErrorText());
        return "";
    }

    LOGD("Login Success!");

    std::string code;

    //outlook: "Inbox"
    success = imap.SelectMailbox(mailbox);
    if (!success) {
        LOGE("imap.SelectMailbox: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("SelectMailbox success!");
    }

    // We can choose to fetch UIDs or sequence numbers.
    bool fetchUids = true;
    // Get the message IDs of all the emails in the mailbox
    CkMessageSet *messageSet = imap.Search("ALL", fetchUids);
    if (!imap.get_LastMethodSuccess()) {
        LOGE("imap.Search: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("Search ALL mail box success!");
    }

    // Fetch the emails into a bundle object:
    CkEmailBundle *bundle = imap.FetchBundle(*messageSet);
    if (!imap.get_LastMethodSuccess()) {
        delete messageSet;
        messageSet = nullptr;
        LOGE("imap.FetchBundle: %s", imap.lastErrorText());
        return "";
    } else {
        LOGD("FetchBundle success!");
    }

    // Loop over the bundle and display the FROM and SUBJECT of each.
    int i = 0;
    int numEmails = bundle->get_MessageCount();
    while (i < numEmails) {
        CkEmail *ckEmail = bundle->GetEmail(i);
        LOGD("email from -> %s", ckEmail->ck_from());
        LOGD("email to -> %s", ckEmail->getToAddr(0));
        LOGD("email subject -> %s", ckEmail->subject());

        if (std::string(ckEmail->ck_from()).find("Facebook") != std::string::npos ||
            std::string(ckEmail->getToAddr(0)).find(email) != std::string::npos) {
            LOGD("body: %s", ckEmail->subject());
            std::cmatch veriCodeMatchValue;
            if (regex_search(ckEmail->subject(), veriCodeMatchValue, std::regex("\\d{5,7}"))) {
                code = veriCodeMatchValue[0];
                //bool SetFlag(int msgId, bool bUid, const char *flagName, int value);
                // delete email
                imap.SetFlag(ckEmail->GetImapUid(), true, "Deleted", 1);
            }
        }
        delete ckEmail;
        i = i + 1;
    }

    // Expunge and close the mailbox.
    success = imap.ExpungeAndClose();

    delete messageSet;
    delete bundle;

    // Disconnect from the IMAP server.
    success = imap.Disconnect();
    LOGD("code: %s", code.data());
    return code;
}

std::string WebAPI::getTiktokCodeFromHotmail(const char * email, const char * password) const {
    return getCodeFromImap("outlook.office365.com", 993, "Inbox", "TikTok", email, email, password);
}

bool WebAPI::checkLoginHotmail(std::string &email, std::string &password) const
{
    LOGD("email: %s -- passwd: %s", email.data(), password.data());
    CkImap imap;

    // Connect to they Yahoo! IMAP server.
    imap.put_Port(993);
    imap.put_Ssl(true);
    bool success = imap.Connect("outlook.office365.com");
    if (!success)
    {
        LOGE("imap.Connect: %s", imap.lastErrorText());
        return false;
    }
    // Send the non-standard ID command...
    imap.sendRawCommand("ID (\"GUID\" \"1\")");
    if (!imap.get_LastMethodSuccess())
    {
        LOGE("imap.sendRawCommand: %s", imap.lastErrorText());
        return false;
    }

    // Login
    success = imap.Login(email.c_str(), password.c_str());
    if (!success)
    {
        LOGE("imap.Login: %s", imap.lastErrorText());
        return false;
    }

    LOGD("Login Success!");
    return true;
}

std::string WebAPI::tOTP(const char * secretkey) {
    std::string result;
    if(secretkey) {
        // Do the following to calculate the 6-digit decimal Google authenticator token for a base32 secret,
        // given the current system date/time.
        CkCrypt2 crypt;
        result = crypt.totp(secretkey,"base32","0","",30,6,-1,"sha1");
    }
    return result;
}
