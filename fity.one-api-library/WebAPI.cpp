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
#include <dirent.h>
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
    case WebAPI::PLATFORM_CHROME:
        en_cert = en_cert1;
        en_privatekey = en_privatekey1;
        keyPass = "client1";
        break;
    case WebAPI::PLATFORM_LDPLAYER:
        en_cert = en_cert2;
        en_privatekey = en_privatekey2;
        keyPass = "client2";
        break;
    case WebAPI::PLATFORM_ANDROID:
        en_cert = en_cert3;
        en_privatekey = en_privatekey3;
        keyPass = "client3";
        break;
    case WebAPI::PLATFORM_ANDROID_WEBVIEW:
        en_cert = en_cert4;
        en_privatekey = en_privatekey4;
        keyPass = "client4";
        break;
    case WebAPI::PLATFORM_IOS:
        en_cert = en_cert5;
        en_privatekey = en_privatekey5;
        keyPass = "client5";
        break;
    case WebAPI::PLATFORM_IOS_WEBVIEW:
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
    LOGD("privKey: %s",cert.getEncoded());

    CkPrivateKey privKey;
    if (!privKey.LoadEncryptedPem(decrypt(en_privatekey.data(),md5("dang.phong").data(),md5("pdt").substr(0,16).data()).data(),keyPass.data())) {
        LOGE("load key error: %s",privKey.lastErrorText());
        return false;
    };
    LOGD("privKey: %s",privKey.getPkcs8Pem());
    // Associate the private key with the cert.
    if (!cert.SetPrivateKey(privKey)) {
        LOGE("SetPrivateKey error: %s",cert.lastErrorText());
        return false;
    }

    return true;
}

WebAPI::WebAPI()
{
    m_listKey.emplace_back("signInName");
    m_listKey.emplace_back("uaid");
    m_listKey.emplace_back("includeSuggestions");
    m_listKey.emplace_back("uiflvr");
    m_listKey.emplace_back("scid");
    m_listKey.emplace_back("hpgid");
    m_listKey.emplace_back("Signup_MemberNamePage_Client");
    m_listKey.emplace_back("evts");
    m_listKey.emplace_back("perf");
    m_listKey.emplace_back("data");
    m_listKey.emplace_back("navigation");
    m_listKey.emplace_back("type");
    m_listKey.emplace_back("redirectCount");
    m_listKey.emplace_back("timing");
    m_listKey.emplace_back("navigationStart");
    m_listKey.emplace_back("unloadEventStart");
    m_listKey.emplace_back("unloadEventEnd");
    m_listKey.emplace_back("redirectStart");
    m_listKey.emplace_back("redirectEnd");
    m_listKey.emplace_back("fetchStart");
    m_listKey.emplace_back("domainLookupStart");
    m_listKey.emplace_back("domainLookupEnd");
    m_listKey.emplace_back("connectStart");
    m_listKey.emplace_back("connectEnd");
    m_listKey.emplace_back("secureConnectionStart");
    m_listKey.emplace_back("requestStart");
    m_listKey.emplace_back("responseStart");
    m_listKey.emplace_back("responseEnd");
    m_listKey.emplace_back("domLoading");
    m_listKey.emplace_back("domInteractive");
    m_listKey.emplace_back("domContentLoadedEventStart");
    m_listKey.emplace_back("domContentLoadedEventEnd");
    m_listKey.emplace_back("domComplete");
    m_listKey.emplace_back("loadEventStart");
    m_listKey.emplace_back("loadEventEnd");
    m_listKey.emplace_back("customLoadEventEnd");
    m_listKey.emplace_back("entries");
    m_listKey.emplace_back("name");
    m_listKey.emplace_back("entryType");
    m_listKey.emplace_back("startTime");
    m_listKey.emplace_back("duration");
    m_listKey.emplace_back("initiatorType");
    m_listKey.emplace_back("nextHopProtocol");
    m_listKey.emplace_back("workerStart");
    m_listKey.emplace_back("transferSize");
    m_listKey.emplace_back("encodedBodySize");
    m_listKey.emplace_back("decodedBodySize");
    m_listKey.emplace_back("serverTiming");
    m_listKey.emplace_back("navigate");
    m_listKey.emplace_back("resource");
    m_listKey.emplace_back("link");
    m_listKey.emplace_back("script");
    m_listKey.emplace_back("h2");
    m_listKey.emplace_back("img");
    m_listKey.emplace_back("css");
    m_listKey.emplace_back("first");
    m_listKey.emplace_back("paint");
    m_listKey.emplace_back("contentful");
    m_listKey.emplace_back("connection");
    m_listKey.emplace_back("onchange");
    m_listKey.emplace_back("effectiveType");
    m_listKey.emplace_back("3g");
    m_listKey.emplace_back("rtt");
    m_listKey.emplace_back("downlink");
    m_listKey.emplace_back("saveData");
    m_listKey.emplace_back("tm");
    m_listKey.emplace_back("cm");
    m_listKey.emplace_back("tcxt");
    m_listKey.emplace_back("cntry");
    m_listKey.emplace_back("svr");
    m_listKey.emplace_back("dc");
    m_listKey.emplace_back("westus2");
    m_listKey.emplace_back("ri");
    m_listKey.emplace_back("wusXXXX000H");
    m_listKey.emplace_back("ver");
    m_listKey.emplace_back("v");
    m_listKey.emplace_back("rt");
    m_listKey.emplace_back("et");
    m_listKey.emplace_back("hst");
    m_listKey.emplace_back("signup");
    m_listKey.emplace_back("live");
    m_listKey.emplace_back("com");
    m_listKey.emplace_back("nt");
    m_listKey.emplace_back("av");
    m_listKey.emplace_back("pageApiId");
    m_listKey.emplace_back("clientDetails");
    m_listKey.emplace_back("country");
    m_listKey.emplace_back("userAction");
    m_listKey.emplace_back("source");
    m_listKey.emplace_back("PageView");
    m_listKey.emplace_back("clientTelemetryData");
    m_listKey.emplace_back("category");
    m_listKey.emplace_back("PageLoad");
    m_listKey.emplace_back("pageName");
    m_listKey.emplace_back("Signup_MemberNamePage");
    m_listKey.emplace_back("eventInfo");
    m_listKey.emplace_back("timestamp");
    m_listKey.emplace_back("perceivedPlt");
    m_listKey.emplace_back("networkLatency");
    m_listKey.emplace_back("appVersion");
    m_listKey.emplace_back("networkType");
    m_listKey.emplace_back("precaching");
    m_listKey.emplace_back("bundleVersion");
    m_listKey.emplace_back("deviceYear");
    m_listKey.emplace_back("isMaster");
    m_listKey.emplace_back("bundleHits");
    m_listKey.emplace_back("bundleMisses");
    m_listKey.emplace_back("btData");
    m_listKey.emplace_back("cxhFunctionRes");
    m_listKey.emplace_back("Signup_PasswordPage_Client");
    m_listKey.emplace_back("Signup_PasswordPage");
    m_listKey.emplace_back("Signup_ProfileAccrualPage_Client");
    m_listKey.emplace_back("Action_ClientSideTelemetry");
    m_listKey.emplace_back("Signup_ProfileAccrualPage");
    m_listKey.emplace_back("Signup_BirthdatePage_Client");
    m_listKey.emplace_back("Signup_BirthdatePage");
    m_listKey.emplace_back("Signup_HipPage_Client");
    m_listKey.emplace_back("Signup_HipPage");
    m_listKey.emplace_back("Timestamp");
    m_listKey.emplace_back("Timezone");
    m_listKey.emplace_back("PostStartTime");
    m_listKey.emplace_back("SessionID");
    m_listKey.emplace_back("PartnerId");
    m_listKey.emplace_back("Events");
    m_listKey.emplace_back("at");
    m_listKey.emplace_back("keydown");
    m_listKey.emplace_back("tid");
    m_listKey.emplace_back("MemberName");
    m_listKey.emplace_back("s");
    m_listKey.emplace_back("k");
    m_listKey.emplace_back("keyup");
    m_listKey.emplace_back("SubmitIndex");
    m_listKey.emplace_back("Browser");
    m_listKey.emplace_back("UserAgent");
    m_listKey.emplace_back("CookieEnabled");
    m_listKey.emplace_back("JavaEnabled");
    m_listKey.emplace_back("ScreenDepth");
    m_listKey.emplace_back("ScreenHeight");
    m_listKey.emplace_back("ScreenWidth");
    m_listKey.emplace_back("WindowHeight");
    m_listKey.emplace_back("WindowWidth");
    m_listKey.emplace_back("PageHeight");
    m_listKey.emplace_back("PageWidth");
    m_listKey.emplace_back("Language");
    m_listKey.emplace_back("Plugins");
    m_listKey.emplace_back("mousemove");
    m_listKey.emplace_back("dx");
    m_listKey.emplace_back("dy");
    m_listKey.emplace_back("x");
    m_listKey.emplace_back("y");
    m_listKey.emplace_back("click");
    m_listKey.emplace_back("LastName");
    m_listKey.emplace_back("b");
    m_listKey.emplace_back("focus");
    m_listKey.emplace_back("FirstName");
    m_listKey.emplace_back("CheckAvailStateMap");
    m_listKey.emplace_back("dajdfjoaiejrwer2342");
    m_listKey.emplace_back("hotmail");
    m_listKey.emplace_back("undefined");
    m_listKey.emplace_back("EvictionWarningShown");
    m_listKey.emplace_back("UpgradeFlowToken");
    m_listKey.emplace_back("MemberNameChangeCount");
    m_listKey.emplace_back("MemberNameAvailableCount");
    m_listKey.emplace_back("MemberNameUnavailableCount");
    m_listKey.emplace_back("CipherValue");
    m_listKey.emplace_back("SKI");
    m_listKey.emplace_back("BirthDate");
    m_listKey.emplace_back("Country");
    m_listKey.emplace_back("IsOptOutEmailDefault");
    m_listKey.emplace_back("IsOptOutEmailShown");
    m_listKey.emplace_back("IsOptOutEmail");
    m_listKey.emplace_back("LW");
    m_listKey.emplace_back("SiteId");
    m_listKey.emplace_back("IsRDM");
    m_listKey.emplace_back("WReply");
    m_listKey.emplace_back("ReturnUrl");
    m_listKey.emplace_back("SignupReturnUrl");
    m_listKey.emplace_back("SuggestedAccountType");
    m_listKey.emplace_back("OUTLOOK");
    m_listKey.emplace_back("SuggestionType");
    m_listKey.emplace_back("Locked");
    m_listKey.emplace_back("HFId");
    m_listKey.emplace_back("HType");
    m_listKey.emplace_back("visual");
    m_listKey.emplace_back("HSId");
    m_listKey.emplace_back("HId");
    m_listKey.emplace_back("HSol");
    m_listKey.emplace_back("acctcdn");
    m_listKey.emplace_back("hrcdn");
    m_listKey.emplace_back("vendor");
    m_listKey.emplace_back("common");
    m_listKey.emplace_back("pageLoadTime");
    m_listKey.emplace_back("msauth");
    m_listKey.emplace_back("acctcdnmsftuswe");
    m_listKey.emplace_back("FSSFZE");
    m_listKey.emplace_back("acctcdnvzeuno");
    m_listKey.emplace_back("device");
    m_listKey.emplace_back("DataRequest");
    m_listKey.emplace_back("fbundle");
    m_listKey.emplace_back("isProxy");
    m_listKey.emplace_back("OLfvCcbv");
    m_listKey.emplace_back("time_ms");
    m_listKey.emplace_back("WSQWA");
    m_listKey.emplace_back("hipTemplate");
    m_listKey.emplace_back("watsonestoppel");
    m_listKey.emplace_back("douglascrockford");
    m_listKey.emplace_back("ufeff");
    m_listKey.emplace_back("clientTelemetry");
    m_listKey.emplace_back("TimestampSecret");
    m_listKey.emplace_back("amtcxt");
    m_listKey.emplace_back("UnauthSessionId");
    m_listKey.emplace_back("Auryc");
    m_listKey.emplace_back("TelemetryContext");
    m_listKey.emplace_back("ApiRequest");
    m_listKey.emplace_back("MLuaF");
    m_listKey.emplace_back("ApiCall");
    m_listKey.emplace_back("LGseWNAB");
    m_listKey.emplace_back("responseText");
    m_listKey.emplace_back("credentials");
    m_listKey.emplace_back("trackDwellTime");
    m_listKey.emplace_back("HUBM");
    m_listKey.emplace_back("ResponseHeader");
    m_listKey.emplace_back("apiUseIpt");
    m_listKey.emplace_back("SKHD");
    m_listKey.emplace_back("correlationId");
    m_listKey.emplace_back("wlPreferIpt");
    m_listKey.emplace_back("hxRSU");
    m_listKey.emplace_back("view_time");
    m_listKey.emplace_back("apiCanary");
    m_listKey.emplace_back("DCZLE");
    m_listKey.emplace_back("WLXAccount");
    m_listKey.emplace_back("ClientPerf");
    m_listKey.emplace_back("batchTrack");
    m_listKey.emplace_back("sessionId");
    m_listKey.emplace_back("TsGr");
    m_listKey.emplace_back("cxhFunction");
    m_listKey.emplace_back("pageId");
    m_listKey.emplace_back("Qfrac");
    m_listKey.emplace_back("wutPOWE");
    m_listKey.emplace_back("UBQTR");
    m_listKey.emplace_back("TelemetryResourceBundle");
    m_listKey.emplace_back("ApiId");
    m_listKey.emplace_back("major");
    m_listKey.emplace_back("scuXXXX");
    m_listKey.emplace_back("facctcdnmsftuswe");
    m_listKey.emplace_back("XQZS");
    m_listKey.emplace_back("marchingAnts");
    m_listKey.emplace_back("GX");
    m_listKey.emplace_back("pwdless");
    m_listKey.emplace_back("TimeLoad");
    m_listKey.emplace_back("fclient");
    m_listKey.emplace_back("KGZU");
    m_listKey.emplace_back("fSessionID");
    m_listKey.emplace_back("UFE");
    m_listKey.emplace_back("ValidationBehavior");
    m_listKey.emplace_back("fservices");
    m_listKey.emplace_back("cnvCtrlBg");
    m_listKey.emplace_back("facctcdnvzeuno");
    m_listKey.emplace_back("ffwlink");
    m_listKey.emplace_back("EBZWQ");
    m_listKey.emplace_back("fLinkID");
    m_listKey.emplace_back("permission");
    m_listKey.emplace_back("JANR");
    m_listKey.emplace_back("memberNameType");
    m_listKey.emplace_back("EASI");
    m_listKey.emplace_back("CXH");
    m_listKey.emplace_back("IDPS");
    m_listKey.emplace_back("UnifiedHeader");
    m_listKey.emplace_back("CXHMBinary");
    m_listKey.emplace_back("YXVM");
    m_listKey.emplace_back("TimeClick");
    m_listKey.emplace_back("NASAKH");
    m_listKey.emplace_back("mktLocale");
    m_listKey.emplace_back("converged");
    m_listKey.emplace_back("msweb");
    m_listKey.emplace_back("messageHandle");
    m_listKey.emplace_back("SessionStorage");
    m_listKey.emplace_back("WizardExternal");
    m_listKey.emplace_back("VBCFZ");
    m_listKey.emplace_back("lwsignup");
    m_listKey.emplace_back("lrmen");
    m_listKey.emplace_back("iPageElt");
    m_listKey.emplace_back("GCPpM");
    m_listKey.emplace_back("hipContent");
    m_listKey.emplace_back("BNAX");
    m_listKey.emplace_back("TimePressed");
    m_listKey.emplace_back("CBU");
    m_listKey.emplace_back("signupTemplates");
    m_listKey.emplace_back("ESKN");
    m_listKey.emplace_back("DeviceTicket");
    m_listKey.emplace_back("FVE");
    m_listKey.emplace_back("fieldset");
    m_listKey.emplace_back("dropdownCaret");
    m_listKey.emplace_back("ariaLblCountry");
    m_listKey.emplace_back("easiSwitch");
    m_listKey.emplace_back("CTKGLIg");
    m_listKey.emplace_back("associate");
    m_listKey.emplace_back("Tfmuw");
    m_listKey.emplace_back("MembernamePasswordProfile");
    m_listKey.emplace_back("MembernameEn");
    m_listKey.emplace_back("lblNewPwd");
    m_listKey.emplace_back("WMUDW");
    m_listKey.emplace_back("lblVerification");
    m_listKey.emplace_back("hipDesc");
    m_listKey.emplace_back("LAUC");
    m_listKey.emplace_back("Whoops");
    m_listKey.emplace_back("fmicrosoft");
    m_listKey.emplace_back("prefetchPlt");
    m_listKey.emplace_back("phantom");
    m_listKey.emplace_back("gk2_exposure");
    m_listValue.emplace_back("ThermalHAL-UTIL");
    m_listValue.emplace_back("ActivityManager");
    m_listValue.emplace_back("[07_05_01_35_30530]");
    m_listValue.emplace_back("getTaskSnapshot");
    m_listValue.emplace_back("ActivityRecordf9f2944");
    m_listValue.emplace_back("19690comgoogleandroidinputmethodlatintrainu0a79");
    m_listValue.emplace_back("comgoogleandroidgmsautofillserviceAutofillService");
    m_listValue.emplace_back("androidappIntentReceiverLeaked");
    m_listValue.emplace_back("androidappLoadedApk$ReceiverDispatcher<init>LoadedApkjava1429");
    m_listValue.emplace_back("androidappLoadedApkgetReceiverDispatcherLoadedApkjava1210");
    m_listValue.emplace_back("androidappContextImplregisterReceiverInternalContextImpljava1476");
    m_listValue.emplace_back("androidappContextImplregisterReceiverContextImpljava1449");
    m_listValue.emplace_back("androidappContextImplregisterReceiverContextImpljava1437");
    m_listValue.emplace_back("androidcontentContextWrapperregisterReceiverContextWrapperjava623");
    m_listValue.emplace_back("lje<init>comgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("lht<init>comgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("kwiacomgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("cbazacomgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("kwqacomgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("100306-3067585863");
    m_listValue.emplace_back("kutbcomgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("ldzonFillRequestcomgoogleandroidgms@201515026@201515");
    m_listValue.emplace_back("androidserviceautofill-$$Lambda$I0gCKFrBTO70VZfSZTq2fj-wyG8acceptUnknown");
    m_listValue.emplace_back("comandroidinternalutilfunctionpooledPooledLambdaImpldoInvokePooledLambdaImpljava287");
    m_listValue.emplace_back("comandroidinternalutilfunctionpooledPooledLambdaImplinvokePooledLambdaImpljava182");
    m_listValue.emplace_back("comandroidinternalutilfunctionpooledOmniFunctionrunOmniFunctionjava77");
    m_listValue.emplace_back("androidosHandlerhandleCallbackHandlerjava873");
    m_listValue.emplace_back("androidosHandlerdispatchMessageHandlerjava99");
    m_listValue.emplace_back("androidosLooperloopLooperjava193");
    m_listValue.emplace_back("androidappActivityThreadmainActivityThreadjava6746");
    m_listValue.emplace_back("javalangreflectMethodinvokeNative");
    m_listValue.emplace_back("comandroidinternalosRuntimeInit$MethodAndArgsCallerrunRuntimeInitjava493");
    m_listValue.emplace_back("comandroidinternalosZygoteInitmainZygoteInitjava858");
    m_listValue.emplace_back("actandroidintentactionMAIN");
    m_listValue.emplace_back("cat[androidintentcategoryLAUNCHER]");
    m_listValue.emplace_back("xyzautofarmerapp");
    m_listValue.emplace_back("xyzautofarmerappxyzautofarmerappMainActivity");
    m_listValue.emplace_back("ProcessCpuTracker");
    m_listValue.emplace_back("xyzautofarmerappMainActivity");
    m_listValue.emplace_back("19534xyzautofarmerapp");
    m_listValue.emplace_back("1205system_server");
    m_listValue.emplace_back("641mediacodec");
    m_listValue.emplace_back("1578comandroidsystemui");
    m_listValue.emplace_back("1760comandroidphone");
    m_listValue.emplace_back("1569comgoogleandroidinputmethodlatin");
    m_listValue.emplace_back("465androidhardwaresensors@10-service");
    m_listValue.emplace_back("1726dataservices");
    m_listValue.emplace_back("2170comqualcommqtiservicessecureuisui_service");
    m_listValue.emplace_back("19451kworkeru86");
    m_listValue.emplace_back("1745comqualcommqtitelephonyservice");
    m_listValue.emplace_back("2157comandroidse");
    m_listValue.emplace_back("593mediaextractor");
    m_listValue.emplace_back("19448kworkeru84");
    m_listValue.emplace_back("2268comgoogleandroidgmspersistent");
    m_listValue.emplace_back("273mmc-cmdqd0");
    m_listValue.emplace_back("357hwservicemanager");
    m_listValue.emplace_back("427adsp_IPCRTR");
    m_listValue.emplace_back("460androidhardwaregraphicscomposer@21-service");
    m_listValue.emplace_back("490surfaceflinger");
    m_listValue.emplace_back("11862kworkeru82");
    m_listValue.emplace_back("31926kworker05");
    m_listValue.emplace_back("450androidhardwareaudio@20-service");
    m_listValue.emplace_back("487audioserver");
    m_listValue.emplace_back("608mediametrics");
    m_listValue.emplace_back("640androidhardwarecameraprovider@24-service");
    m_listValue.emplace_back("2393comgoogleandroidgms");
    m_listValue.emplace_back("9411comandroidsettings");
    m_listValue.emplace_back("15319comfacebookkatani");
    m_listValue.emplace_back("15473comfacebookkatani_43472e33-1a1c-69c1-aece-1488c79a8af3txt");
    m_listValue.emplace_back("18851comgoogleandroidyoutube");
    m_listValue.emplace_back("19534autofarmerapp");
    m_listValue.emplace_back("ProcessRecordb1da96c");
    m_listValue.emplace_back("actandroidintentactionDROPBOX_ENTRY_ADDED");
    m_listValue.emplace_back("comgoogleandroidgmschimeraGmsIntentOperationService$PersistentTrustedReceiver");
    m_listValue.emplace_back("Type0avg38612614min37307003max40602");
    m_listValue.emplace_back("[07_05_01_36_00533]");
    m_listValue.emplace_back("[07_05_01_36_30537]");
    m_listValue.emplace_back("[07_05_01_37_00541]");
    m_listValue.emplace_back("[07_05_01_37_30545]");
    m_listValue.emplace_back("[07_05_01_38_00547]");
    m_listValue.emplace_back("[07_05_01_38_30550]");
    m_listValue.emplace_back("[07_05_01_39_00553]");
    m_listValue.emplace_back("[07_05_01_39_30556]");
    m_listValue.emplace_back("[07_05_01_40_00559]");
    m_listValue.emplace_back("UsageStatsService");
    m_listValue.emplace_back("[07_05_01_40_30562]");
    m_listValue.emplace_back("[07_05_01_41_00567]");
    m_listValue.emplace_back("[07_05_01_41_30570]");
    m_listValue.emplace_back("[07_05_01_42_00573]");
    m_listValue.emplace_back("eventTime81759161");
    m_listValue.emplace_back("PowerManagerService");
    m_listValue.emplace_back("DisplayPowerController");
    m_listValue.emplace_back("KernelCpuSpeedReader");
    m_listValue.emplace_back("KernelUidCpuTimeReader");
    m_listValue.emplace_back("DisplayManagerService");
    m_listValue.emplace_back("PowerManagerServiceDisplay");
    m_listValue.emplace_back("DreamManagerService");
    m_listValue.emplace_back("DreamController");
    m_listValue.emplace_back("tagDreamManagerService");
    m_listValue.emplace_back("PowerManagerServiceBroadcasts");
    m_listValue.emplace_back("KeyguardStatusView");
    m_listValue.emplace_back("KeyguardDisplayManager");
    m_listValue.emplace_back("ActivityRecord326bf9");
    m_listValue.emplace_back("[07_05_01_42_30576]");
    m_listValue.emplace_back("[07_05_01_43_00579]");
    m_listValue.emplace_back("ConnectivityService");
    m_listValue.emplace_back("INTERNET&NOT_RESTRICTED&TRUSTED");
    m_listValue.emplace_back("[07_05_01_43_30582]");
    m_listValue.emplace_back("[07_05_01_44_00585]");
    m_listValue.emplace_back("[07_05_01_44_30588]");
    m_listValue.emplace_back("[07_05_01_45_00591]");
    m_listValue.emplace_back("comgoogleandroidgmsstatsserviceDropBoxEntryAddedReceiver");
    m_listValue.emplace_back("[07_05_01_45_30594]");
    m_listValue.emplace_back("[07_05_01_46_00597]");
    m_listValue.emplace_back("[07_05_01_46_30600]");
    m_listValue.emplace_back("[07_05_01_47_00603]");
    m_listValue.emplace_back("[07_05_01_47_30606]");
    m_listValue.emplace_back("[07_05_01_48_00609]");
    m_listValue.emplace_back("[07_05_01_48_30612]");
    m_listValue.emplace_back("[07_05_01_49_00615]");
    m_listValue.emplace_back("[07_05_01_49_30618]");
    m_listValue.emplace_back("[07_05_01_50_00621]");
    m_listValue.emplace_back("[07_05_01_50_30624]");
    m_listValue.emplace_back("[07_05_01_51_00627]");
    m_listValue.emplace_back("Type0avg36651897min34141003max39285004");
    m_listValue.emplace_back("[07_05_01_51_30630]");
    m_listValue.emplace_back("[07_05_01_52_00633]");
    m_listValue.emplace_back("[07_05_01_52_30636]");
    m_listValue.emplace_back("[07_05_01_53_00639]");
    m_listValue.emplace_back("[07_05_01_53_30642]");
    m_listValue.emplace_back("[07_05_01_54_00645]");
    m_listValue.emplace_back("[07_05_01_54_30648]");
    m_listValue.emplace_back("[07_05_01_55_00651]");
    m_listValue.emplace_back("[07_05_01_55_30654]");
    m_listValue.emplace_back("[07_05_01_56_00657]");
    m_listValue.emplace_back("[07_05_01_56_30660]");
    m_listValue.emplace_back("[07_05_01_57_00663]");
    m_listValue.emplace_back("24376comgoogleandroidgmssnetu0a15");
    m_listValue.emplace_back("24415comgoogleandroidmusicmainu0a62");
    m_listValue.emplace_back("24428comvinsmartcontactsu0a16");
    m_listValue.emplace_back("comgoogleandroidappsphotos");
    m_listValue.emplace_back("ProcessRecorddf324a1");
    m_listValue.emplace_back("NotificationService");
    m_listValue.emplace_back("6484comandroidproviderscalendaru0a13");
    m_listValue.emplace_back("[07_05_01_57_30666]");
    m_listValue.emplace_back("[07_05_01_58_00670]");
    m_listValue.emplace_back("[07_05_01_58_30673]");
    m_listValue.emplace_back("[07_05_01_59_00675]");
    m_listValue.emplace_back("BatteryExternalStatsWorker");
    m_listValue.emplace_back("sysdevicessystemcpucpu0cpufreqstatstime_in_state");
    m_listValue.emplace_back("[07_05_01_59_30678]");
    m_listValue.emplace_back("[07_05_02_00_00681]");
    m_listValue.emplace_back("[07_05_02_00_30684]");
    m_listValue.emplace_back("[07_05_02_01_00687]");
    m_listValue.emplace_back("[07_05_02_01_30690]");
    m_listValue.emplace_back("[07_05_02_02_00693]");
    m_listValue.emplace_back("[07_05_02_02_30696]");
    m_listValue.emplace_back("[07_05_02_03_00699]");
    m_listValue.emplace_back("[07_05_02_03_30702]");
    m_listValue.emplace_back("[07_05_02_04_00705]");
    m_listValue.emplace_back("[07_05_02_04_30708]");
    m_listValue.emplace_back("[07_05_02_05_00711]");
    m_listValue.emplace_back("[07_05_02_05_30715]");
    m_listValue.emplace_back("uidpid1008511774");
    m_listValue.emplace_back("uidpid1008111799");
    m_listValue.emplace_back("[07_05_02_06_00718]");
    m_listValue.emplace_back("[07_05_02_06_30721]");
    m_listValue.emplace_back("Type0avg33470116min3308max34141003");
    m_listValue.emplace_back("[07_05_02_07_00724]");
    m_listValue.emplace_back("[07_05_02_07_30727]");
    m_listValue.emplace_back("[07_05_02_08_00730]");
    m_listValue.emplace_back("[07_05_02_08_30733]");
    m_listValue.emplace_back("[07_05_02_09_00736]");
    m_listValue.emplace_back("[07_05_02_09_30739]");
    m_listValue.emplace_back("[07_05_02_10_00742]");
    m_listValue.emplace_back("[07_05_02_10_30745]");
    m_listValue.emplace_back("[07_05_02_11_00748]");
    m_listValue.emplace_back("[07_05_02_11_30751]");
    m_listValue.emplace_back("[07_05_02_12_00754]");
    m_listValue.emplace_back("[07_05_02_12_30757]");
    m_listValue.emplace_back("[07_05_02_13_00760]");
    m_listValue.emplace_back("[07_05_02_13_30763]");
    m_listValue.emplace_back("[07_05_02_14_00766]");
    m_listValue.emplace_back("[07_05_02_14_30769]");
    m_listValue.emplace_back("[07_05_02_15_00772]");
    m_listValue.emplace_back("[07_05_02_15_30775]");
    m_listValue.emplace_back("[07_05_02_16_00778]");
    m_listValue.emplace_back("[07_05_02_16_30781]");
    m_listValue.emplace_back("[07_05_02_17_00784]");
    m_listValue.emplace_back("[07_05_02_17_30787]");
    m_listValue.emplace_back("[07_05_02_18_00790]");
    m_listValue.emplace_back("[07_05_02_18_30793]");
    m_listValue.emplace_back("[07_05_02_19_00796]");
    m_listValue.emplace_back("[07_05_02_19_30799]");
    m_listValue.emplace_back("[07_05_02_20_00802]");
    m_listValue.emplace_back("[07_05_02_20_30805]");
    m_listValue.emplace_back("[07_05_02_21_00808]");
    m_listValue.emplace_back("[07_05_02_21_30811]");
    m_listValue.emplace_back("[07_05_02_22_00814]");
    m_listValue.emplace_back("[07_05_02_22_30817]");
    m_listValue.emplace_back("Type0avg33133076min33030003max33383003");
    m_listValue.emplace_back("[07_05_02_23_00820]");
    m_listValue.emplace_back("[07_05_02_23_30823]");
    m_listValue.emplace_back("[07_05_02_24_00826]");
    m_listValue.emplace_back("[07_05_02_24_30829]");
    m_listValue.emplace_back("[07_05_02_25_00832]");
    m_listValue.emplace_back("[07_05_02_25_30835]");
    m_listValue.emplace_back("[07_05_02_26_00838]");
    m_listValue.emplace_back("[07_05_02_26_30841]");
    m_listValue.emplace_back("[07_05_02_27_00844]");
    m_listValue.emplace_back("[07_05_02_27_30847]");
    m_listValue.emplace_back("[07_05_02_28_00850]");
    m_listValue.emplace_back("[07_05_02_28_30853]");
    m_listValue.emplace_back("[07_05_02_29_00856]");
    m_listValue.emplace_back("[07_05_02_29_30859]");
    m_listValue.emplace_back("[07_05_02_30_00862]");
    m_listValue.emplace_back("[07_05_02_30_30865]");
    m_listValue.emplace_back("31768comfacebookkatanku0a139");
    m_listValue.emplace_back("actcomfacebookmessagingipcpeersPROD");
    m_listValue.emplace_back("comfacebookkatank");
    m_listValue.emplace_back("[07_05_02_31_00868]");
    m_listValue.emplace_back("actcomfacebookprofiloMAIN_PROCESS_STARTED_V4");
    m_listValue.emplace_back("6547comandroidchromeu0a61");
    m_listValue.emplace_back("NetworkRequestInfo");
    m_listValue.emplace_back("binderDiedNetworkRequest");
    m_listValue.emplace_back("androidosBinderProxy@b198850");
    m_listValue.emplace_back("comgoogleandroidappsmessaging");
    m_listValue.emplace_back("comfacebookpermissionprodFB_APP_COMMUNICATION");
    m_listValue.emplace_back("BroadcastFilteree52623");
    m_listValue.emplace_back("cmpcomfacebookkatankcomfacebookmqttliteMqttService");
    m_listValue.emplace_back("hcomandroidservernotificationNotificationManagerService$WorkerHandler");
    m_listValue.emplace_back("actX2KCNETWORKING_ACTIVE");
    m_listValue.emplace_back("BroadcastFilter5f64bf1");
    m_listValue.emplace_back("ReceiverList2cd352");
    m_listValue.emplace_back("actandroidnetconnCONNECTIVITY_CHANGE");
    m_listValue.emplace_back("actandroidnetconnINET_CONDITION_ACTION");
    m_listValue.emplace_back("BroadcastFilter48baa36");
    m_listValue.emplace_back("undrawn[Window879930d");
    m_listValue.emplace_back("actmessenger_diode_badge_sync_action");
    m_listValue.emplace_back("BroadcastFilterc8f6628");
    m_listValue.emplace_back("BroadcastFilter15ed4db");
    m_listValue.emplace_back("ReceiverList6b9ac4b");
    m_listValue.emplace_back("ReceiverListd82d798");
    m_listValue.emplace_back("comfacebookkatank10139u0");
    m_listValue.emplace_back("actX2KCNETWORKING_INACTIVE");
    m_listValue.emplace_back("BroadcastFilter7b11172");
    m_listValue.emplace_back("ReceiverList89a9ea");
    m_listValue.emplace_back("remote114791a");
    m_listValue.emplace_back("comfacebookkatani10138u0");
    m_listValue.emplace_back("remote9d73d7b");
    m_listValue.emplace_back("remote6654bdd");
    m_listValue.emplace_back("remote7db7dd5");
    m_listValue.emplace_back("[07_05_02_31_30871]");
    m_listValue.emplace_back("[07_05_02_32_00874]");
    m_listValue.emplace_back("[07_05_02_32_30877]");
    m_listValue.emplace_back("[07_05_02_33_00879]");
    m_listValue.emplace_back("[07_05_02_33_30882]");
    m_listValue.emplace_back("[07_05_02_34_00885]");
    m_listValue.emplace_back("[07_05_02_34_30888]");
    m_listValue.emplace_back("[07_05_02_35_00891]");
    m_listValue.emplace_back("[07_05_02_35_30894]");
    m_listValue.emplace_back("[07_05_02_36_00897]");
    m_listValue.emplace_back("[07_05_02_36_30900]");
    m_listValue.emplace_back("[07_05_02_37_00903]");
    m_listValue.emplace_back("[07_05_02_37_30906]");
    m_listValue.emplace_back("[07_05_02_38_00909]");
    m_listValue.emplace_back("Type0avg33585625min33383003max34595");
    m_listValue.emplace_back("[07_05_02_38_30912]");
    m_listValue.emplace_back("[07_05_02_39_00915]");
    m_listValue.emplace_back("[07_05_02_39_30918]");
    m_listValue.emplace_back("[07_05_02_40_00921]");
    m_listValue.emplace_back("[07_05_02_40_30924]");
    m_listValue.emplace_back("[07_05_02_41_00927]");
    m_listValue.emplace_back("[07_05_02_41_30930]");
    m_listValue.emplace_back("[07_05_02_42_00933]");
    m_listValue.emplace_back("[07_05_02_42_30936]");
    m_listValue.emplace_back("3239comandroidproviderscalendaru0a13");
    m_listValue.emplace_back("[07_05_02_43_00940]");
    m_listValue.emplace_back("[07_05_02_43_30943]");
    m_listValue.emplace_back("[07_05_02_44_00946]");
    m_listValue.emplace_back("[07_05_02_44_30949]");
    m_listValue.emplace_back("[07_05_02_45_00952]");
    m_listValue.emplace_back("[07_05_02_45_30955]");
    m_listValue.emplace_back("[07_05_02_46_00958]");
    m_listValue.emplace_back("[07_05_02_46_30961]");
    m_listValue.emplace_back("[07_05_02_47_00964]");
    m_listValue.emplace_back("[07_05_02_47_30967]");
    m_listValue.emplace_back("[07_05_02_48_00970]");
    m_listValue.emplace_back("[07_05_02_48_30973]");
    m_listValue.emplace_back("[07_05_02_49_00976]");
    m_listValue.emplace_back("[07_05_02_49_30979]");
    m_listValue.emplace_back("[07_05_02_50_00982]");
    m_listValue.emplace_back("[07_05_02_50_30986]");
    m_listValue.emplace_back("[07_05_02_51_00989]");
    m_listValue.emplace_back("[07_05_02_51_30992]");
    m_listValue.emplace_back("[07_05_02_52_00995]");
    m_listValue.emplace_back("[07_05_02_52_30998]");
    m_listValue.emplace_back("[07_05_02_53_01001]");
    m_listValue.emplace_back("[07_05_02_53_31004]");
    m_listValue.emplace_back("Type0avg33770664min33686max33838");
    m_listValue.emplace_back("[07_05_02_54_01007]");
    m_listValue.emplace_back("[07_05_02_54_31010]");
    m_listValue.emplace_back("[07_05_02_55_01013]");
    m_listValue.emplace_back("5896comgoogleandroidappstachyonu0a76");
    m_listValue.emplace_back("5901comgoogleandroidappsmessagingu0a81");
    m_listValue.emplace_back("cmpcomgoogleandroidappsmessagingshareddatamodelactionexecutionActionExecutorImpl$EmptyService");
    m_listValue.emplace_back("uidpid100765896");
    m_listValue.emplace_back("6026comandroidchromeu0a61");
    m_listValue.emplace_back("9411comandroidsettings1000");
    m_listValue.emplace_back("uidpid100815901");

    m_initState = false;
    m_platform = PLATFORM_UNKNOWN;
    m_token = "";
    m_deviceInfo = "";
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
    bool success_global = glob.UnlockBundle("VONGTH.CB4082020_9kru5rnD5R2h");
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

bool WebAPI::makeDir(const char *folerName)
{
    LOGD("folerName: %s", folerName);
    int status = mkdir(folerName, 0777);
    LOGD("status: %d -- error: %d", status, errno);
    if ((status < 0) && (errno != EEXIST))
    {
        return false;
    }
    else
    {
        return true;
    }
}

std::string WebAPI::getDomain()
{
    switch (m_platform) {
    case WebAPI::PLATFORM_CHROME:
        return "https://api.fity.one/cgi-bin/fityone.1.cgi";
    case WebAPI::PLATFORM_LDPLAYER:
        return "https://api.fity.one/cgi-bin/fityone.2.cgi";
    case WebAPI::PLATFORM_ANDROID:
        return "https://api.fity.one/cgi-bin/fityone.3.cgi";
    case WebAPI::PLATFORM_ANDROID_WEBVIEW:
        return "https://api.fity.one/cgi-bin/fityone.4.cgi";
    case WebAPI::PLATFORM_IOS:
        return "https://api.fity.one/cgi-bin/fityone.5.cgi";
    case WebAPI::PLATFORM_IOS_WEBVIEW:
        return "https://api.fity.one/cgi-bin/fityone.6.cgi";
    default:
        return std::string();
    }
}

std::string WebAPI::getUrlByAPI(std::string api)
{
    return getDomain() + std::string("?api=") + api + std::string("&token=") + m_token;
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

bool WebAPI::initWebAPIs(E_SUPPORTED_PLATFORM platform, const char *token, const char *deviceInfo)
{
    LOGD("initWebAPIs");
    CkJsonObject deviceJson;
    if(platform < PLATFORM_CHROME || platform > PLATFORM_IOS_WEBVIEW) {
        LOGE("");
    } else if (!loadJson(deviceJson, deviceInfo)) {
        LOGE("Could not load device info to Json Object");
    } else if (deviceInfo == nullptr) {
        LOGE("deviceInfo is NULL");
    } else if (token == nullptr) {
        LOGE("token is NULL");
    } else if (std::string(token).empty()) {
        LOGE("Invalid token: %s !", token);
    }
    else
    {
#if 0
        int app_signature = loadSignature(env,getGlobalContext(env));
        deviceJson.UpdateInt("apk_signature_code",app_signature);
#endif

        setInitState(true);
        m_token = std::string(token);
        m_platform = platform;

        switch (m_platform) {
        case WebAPI::PLATFORM_CHROME:
            deviceJson.UpdateString("system","f_system");
            break;
        case WebAPI::PLATFORM_LDPLAYER:
            deviceJson.UpdateString("system","f_care");
            break;
        case WebAPI::PLATFORM_ANDROID:
            deviceJson.UpdateString("system","f_anroid");
            break;
        case WebAPI::PLATFORM_ANDROID_WEBVIEW:
            deviceJson.UpdateString("system","f_android_webview");
            break;
        case WebAPI::PLATFORM_IOS:
            deviceJson.UpdateString("system","f_ios");
            break;
        case WebAPI::PLATFORM_IOS_WEBVIEW:
            deviceJson.UpdateString("system","f_ios_webview");
            break;
        default:
            break;
        }

        m_deviceInfo = std::string(deviceJson.emit());
        LOGD("m_token: %s", m_token.data());
        LOGD("m_deviceInfo: %s", m_deviceInfo.data());
    }

    LOGD("initWebAPIs: %s", (initState() ? "successful" : "failure"));
    return initState();
}

std::string WebAPI::token() const
{
    return m_token;
}

std::string WebAPI::deviceInfo() const
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

    if (sendRequest( __FUNCTION__ , bodyData, response, "config", extraDeviceInfo))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("code") &&
                (server_data->IntOf("code") == 200)) {
                retVal.UpdateBool("success", true);
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
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

    if (sendRequest( __FUNCTION__ , bodyData, response, "config", extraDeviceInfo))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("code") &&
                (server_data->IntOf("code") == 200)) {
                retVal.UpdateBool("success", true);
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
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

    if (sendRequest( __FUNCTION__ ,bodyData, response, "config"))

    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("code") &&
                (server_data->IntOf("code") == 200))
            {
                retVal.UpdateBool("success", true);
            }

            if (server_data->HasMember("version"))
            {
                retVal.UpdateString("version", server_data->stringOf("version"));
            }

            if (server_data->HasMember("new_token"))
            {
                retVal.UpdateString("new_token", server_data->stringOf("new_token"));
            }

            if (server_data->HasMember("data")) {
                const char *data = server_data->stringOf("data");
                CkJsonObject configJson;
                if (loadJson(configJson, data)) {
                    retVal.AddObjectCopyAt(-1, "config", configJson);
                    retVal.UpdateBool("success", true);

                    if (configJson.HasMember("dropboxaccesstoken")) {
                        m_dropBoxToken = std::string(configJson.stringOf("dropboxaccesstoken"));
                    } else {
                        retVal.UpdateString("warning_message",
                                            "Dropboxaccesstoken field is not existed!");
                    }
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getClone(const char *appName)
{
    LOGD("appName: %s", toLowerCase(appName).data());
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetClone");
    bodyData.UpdateString("appname", toLowerCase(appName).data());

    if (sendRequest( __FUNCTION__, bodyData, response, "config"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code"))
            {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data"))
            {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data()))
                {
                    retVal.AddObjectCopyAt(-1, "cloneInfo", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
    }
    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getCloneInfo(const char *appName, const char *clone_info)
{
    LOGD("appName: %s -- clone_info: %s", toLowerCase(appName).data(), clone_info);
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
    bodyData.UpdateString("appname", toLowerCase(appName).data());
    bodyData.UpdateString("clone_info", str.getString());

    if (sendRequest(__FUNCTION__ , bodyData, response, "config"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code"))
            {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data"))
            {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data()))
                {
                    retVal.AddObjectCopyAt(-1, "cloneInfo", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::getStoredClones(const char *appName)
{
    LOGD("");
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetStoredClones");
    bodyData.UpdateString("appname", toLowerCase(appName).data());

    if (sendRequest(__FUNCTION__ , bodyData, response, "config"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code"))
            {
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data"))
            {
                std::string data = server_data->stringOf("data");

                CkJsonArray storedClones;
                storedClones.put_Utf8(true);
                if (storedClones.Load(data.data()))
                {
                    retVal.AddArrayCopyAt(-1, "stored_clones", storedClones);
                } else {
                    LOGE("Load data failed");
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
    }

    LOGD("retVal: %s", retVal.emit());
    return retVal.emit();
}

std::string WebAPI::updateClone(const char * action, const char *appName, const char *cloneJsonPath)
{
    LOGD("action: %s -- appName: %s -- cloneJsonPath: %s",action, toLowerCase(appName).data(), cloneJsonPath);
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
    bodyData.UpdateString("appname", toLowerCase(appName).data());
    bodyData.UpdateString("clone_info", str.getString());

    if (sendRequest( __FUNCTION__ , bodyData, response, "config")) {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data) {

            if (server_data->HasMember("code"))
            {
                retVal.UpdateBool("success", server_data->IntOf("code") == 200);
                retVal.UpdateInt("code", server_data->IntOf("code"));
            }

            if (server_data->HasMember("data"))
            {
                std::string data = server_data->stringOf("data");

                //decrypte password and 2fa
                decryptCloneInfo( data);

                CkJsonObject cloneInfoObj;
                cloneInfoObj.put_Utf8(true);
                if (loadJson(cloneInfoObj,data.data()))
                {
                    retVal.AddObjectCopyAt(-1, "cloneInfo", cloneInfoObj);
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    } else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
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

    if (sendRequest( __FUNCTION__ , bodyData, response, "get-do-actions"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("data"))
            {
                CkJsonArray actionsArr;
                actionsArr.put_Utf8(true);
                if(actionsArr.Load(server_data->stringOf("data")))
                retVal.AddArrayCopyAt(-1, "actions", actionsArr);
            }

            retVal.UpdateBool("success", true);

            if (server_data->HasMember("code"))
            {
                retVal.UpdateInt("code", server_data->IntOf("code"));
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

bool WebAPI::doResult(const char *clone_id, const char *dataJsonPath)
{
    LOGD("clone_id: %s -- dataJsonPath: %s", clone_id, dataJsonPath);
    CkJsonObject bodyData, response, actionObj;
    bodyData.UpdateString("clone_id", clone_id);
    if (loadJson(actionObj,dataJsonPath))
        bodyData.AddObjectCopyAt(-1, "data", actionObj);

    if (sendRequest( __FUNCTION__, bodyData, response, "do-result"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("code")) {
                return server_data->IntOf("code") == 200 ||
                        server_data->IntOf("code") == 400 ||
                        server_data->IntOf("code") == 401;
            }
        }
    }
    return false;
}

std::string WebAPI::getJasmineDefinitions()
{
    LOGD("");
    CkJsonObject retVal;
    retVal.put_Utf8(true);
    retVal.UpdateBool("success", false);

    CkJsonObject bodyData, response;
    bodyData.UpdateString("action", "GetJasmine");

    if (sendRequest( __FUNCTION__, bodyData, response, "config"))
    {
        CkJsonObject *server_data = response.ObjectOf("data");
        if (server_data)
        {
            if (server_data->HasMember("data"))
            {
                CkJsonArray definitionArr;
                definitionArr.put_Utf8(true);
                if(definitionArr.Load(server_data->stringOf("data"))) {
                    retVal.UpdateBool("success", true);
                    retVal.AddArrayCopyAt(-1, "definitions", definitionArr);
                }
            }
        }
        else
        {
            retVal.AddObjectCopyAt(-1, "error_message",response);
        }
    }
    else
    {
        retVal.AddObjectCopyAt(-1, "error_message",response);
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
            if (server_data->HasMember("code")
                && (server_data->IntOf("code") == 200 || server_data->IntOf("code") == 400)) {
                retVal.UpdateBool("success", true);
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
                    retVal.AddObjectCopyAt(-1, "email_object", emailObj);
                }
            }

            if (server_data->HasMember("message"))
            {
                retVal.UpdateString("message", server_data->stringOf("message"));
            }
        }
    }
    else
    {
        retVal.UpdateString("error", "Could not load resp->bodyStr() -> JsonObject");
        retVal.UpdateString("message", "API error!");
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
    const char *rawResponse = nullptr;
    rawResponse = imap.sendRawCommand("ID (\"GUID\" \"1\")");
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
            LOGD("body: %s", ckEmail->body());
            std::cmatch veriCodeMatchValue;
            if (regex_search(ckEmail->body(), veriCodeMatchValue, std::regex("\\d{5,7}"))) {
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
        if (loadJson(deviceInfo,m_deviceInfo.data())) {
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
        if(!getCert(cert,m_platform)) {
            LOGE("GetCert failed!");
            response.UpdateString("error_message", "GetCert failed!");
        } else if(!http.SetSslClientCert(cert)) {
            LOGE("SetSslClientCert error: %s", http.lastErrorText());
            response.UpdateString("error_message", "SetSslClientCert error!");
        } else {
            LOGD("Apply certificate successfully!");
            CkHttpResponse *resp = http.PostJson(getUrlByAPI(api).data(), jsonReqBody.emit());

            if (!http.get_LastMethodSuccess()) {
                response.UpdateString("error_message", http.lastErrorText());
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
                                response.UpdateString("error_message",
                                                      "Could not get server_timestamp");
                            }
                        } else {
                            response.UpdateString("error_message", "Data field is not existed!");
                        }
                    } else {
                        response.UpdateString("error_message",
                                              "Could not load resp->bodyStr() -> JsonObject");
                    }
                } else {
                    response.UpdateString("error_message", "resp->bodyStr() is NULL");
                }
            }
            delete resp;
        }
    }
    else
    {
        response.UpdateString("error_message", "Init failure");
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

std::string WebAPI::getFacebookCodeFromCGBDomainMail(const char * email) const {
    LOGD("email: %s", email);
    return getCodeFromImap("imap.yandex.com", 993, "Spam", "Facebook", email, "admin@bobolala.xyz", "ecstipxneiopwyvx");
}

std::string WebAPI::getTiktokCodeFromCGBDomainMail(const char * email) const {
    LOGD("email: %s", email);
    return getCodeFromImap("imap.yandex.com", 993, "Inbox", "TikTok", email, "admin@bobolala.xyz", "ecstipxneiopwyvx");
}

std::string WebAPI::getFacebookCodeFromHotmail(const char * email, const char * password) const {
    LOGD("email: %s -- passwd: %s", email, password);
    return getCodeFromImap("outlook.office365.com", 993, "Inbox", "Facebook", email, email, password);
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
    const char *rawResponse = nullptr;
    rawResponse = imap.sendRawCommand("ID (\"GUID\" \"1\")");
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
