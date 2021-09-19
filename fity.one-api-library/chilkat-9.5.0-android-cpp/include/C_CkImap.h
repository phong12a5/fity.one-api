// This is a generated source file for Chilkat version 9.5.0.88
#ifndef _C_CkImap_H
#define _C_CkImap_H
#include "chilkatDefs.h"

#include "Chilkat_C.h"


CK_C_VISIBLE_PUBLIC void CkImap_setAbortCheck(HCkImap cHandle, BOOL (*fnAbortCheck)(void));
CK_C_VISIBLE_PUBLIC void CkImap_setPercentDone(HCkImap cHandle, BOOL (*fnPercentDone)(int pctDone));
CK_C_VISIBLE_PUBLIC void CkImap_setProgressInfo(HCkImap cHandle, void (*fnProgressInfo)(const char *name, const char *value));
CK_C_VISIBLE_PUBLIC void CkImap_setTaskCompleted(HCkImap cHandle, void (*fnTaskCompleted)(HCkTask hTask));

CK_C_VISIBLE_PUBLIC void CkImap_setAbortCheck2(HCkImap cHandle, BOOL (*fnAbortCheck2)(void *pContext));
CK_C_VISIBLE_PUBLIC void CkImap_setPercentDone2(HCkImap cHandle, BOOL (*fnPercentDone2)(int pctDone, void *pContext));
CK_C_VISIBLE_PUBLIC void CkImap_setProgressInfo2(HCkImap cHandle, void (*fnProgressInfo2)(const char *name, const char *value, void *pContext));
CK_C_VISIBLE_PUBLIC void CkImap_setTaskCompleted2(HCkImap cHandle, void (*fnTaskCompleted2)(HCkTask hTask, void *pContext));

// setExternalProgress is for C callback functions defined in the external programming language (such as Go)
CK_C_VISIBLE_PUBLIC void CkImap_setExternalProgress(HCkImap cHandle, BOOL on);
CK_C_VISIBLE_PUBLIC void CkImap_setCallbackContext(HCkImap cHandle, void *pContext);

CK_C_VISIBLE_PUBLIC HCkImap CkImap_Create(void);
CK_C_VISIBLE_PUBLIC void CkImap_Dispose(HCkImap handle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getAbortCurrent(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putAbortCurrent(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getAppendSeen(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putAppendSeen(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC int CkImap_getAppendUid(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getAuthMethod(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putAuthMethod(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_authMethod(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getAuthzId(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putAuthzId(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_authzId(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getAutoDownloadAttachments(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putAutoDownloadAttachments(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getAutoFix(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putAutoFix(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getClientIpAddress(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putClientIpAddress(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_clientIpAddress(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getConnectedToHost(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_connectedToHost(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getConnectTimeout(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putConnectTimeout(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getDebugLogFilePath(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putDebugLogFilePath(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_debugLogFilePath(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getDomain(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putDomain(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_domain(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getHeartbeatMs(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putHeartbeatMs(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getHighestModSeq(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_highestModSeq(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getHttpProxyAuthMethod(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putHttpProxyAuthMethod(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_httpProxyAuthMethod(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getHttpProxyDomain(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putHttpProxyDomain(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_httpProxyDomain(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getHttpProxyHostname(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putHttpProxyHostname(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_httpProxyHostname(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getHttpProxyPassword(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putHttpProxyPassword(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_httpProxyPassword(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getHttpProxyPort(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putHttpProxyPort(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getHttpProxyUsername(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putHttpProxyUsername(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_httpProxyUsername(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getKeepSessionLog(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putKeepSessionLog(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getLastAppendedMime(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastAppendedMime(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLastCommand(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastCommand(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLastErrorHtml(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastErrorHtml(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLastErrorText(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastErrorText(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLastErrorXml(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastErrorXml(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLastIntermediateResponse(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastIntermediateResponse(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getLastMethodSuccess(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putLastMethodSuccess(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getLastResponse(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastResponse(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLastResponseCode(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_lastResponseCode(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getLoggedInUser(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_loggedInUser(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getNumMessages(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getPeekMode(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putPeekMode(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC int CkImap_getPercentDoneScale(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putPercentDoneScale(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC int CkImap_getPort(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putPort(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getPreferIpv6(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putPreferIpv6(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC int CkImap_getReadTimeout(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putReadTimeout(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getRequireSslCertVerify(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putRequireSslCertVerify(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getSearchCharset(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSearchCharset(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_searchCharset(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getSelectedMailbox(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_selectedMailbox(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getSendBufferSize(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putSendBufferSize(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getSeparatorChar(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSeparatorChar(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_separatorChar(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getSessionLog(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_sessionLog(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getSocksHostname(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSocksHostname(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_socksHostname(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getSocksPassword(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSocksPassword(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_socksPassword(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getSocksPort(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putSocksPort(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getSocksUsername(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSocksUsername(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_socksUsername(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getSocksVersion(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putSocksVersion(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC int CkImap_getSoRcvBuf(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putSoRcvBuf(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC int CkImap_getSoSndBuf(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putSoSndBuf(HCkImap cHandle, int newVal);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getSsl(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putSsl(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getSslAllowedCiphers(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSslAllowedCiphers(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_sslAllowedCiphers(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getSslProtocol(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putSslProtocol(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_sslProtocol(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getSslServerCertVerified(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getStartTls(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putStartTls(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getTlsCipherSuite(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_tlsCipherSuite(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getTlsPinSet(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putTlsPinSet(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_tlsPinSet(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getTlsVersion(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_tlsVersion(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getUidNext(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC int CkImap_getUidValidity(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_getUncommonOptions(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void CkImap_putUncommonOptions(HCkImap cHandle, const char *newVal);
CK_C_VISIBLE_PUBLIC const char *CkImap_uncommonOptions(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getUtf8(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putUtf8(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC BOOL CkImap_getVerboseLogging(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_putVerboseLogging(HCkImap cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkImap_getVersion(HCkImap cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const char *CkImap_version(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AddPfxSourceData(HCkImap cHandle, HCkByteData pfxBytes, const char *pfxPassword);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AddPfxSourceFile(HCkImap cHandle, const char *pfxFilePath, const char *pfxPassword);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AppendMail(HCkImap cHandle, const char *mailbox, HCkEmail email);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_AppendMailAsync(HCkImap cHandle, const char *mailbox, HCkEmail email);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AppendMime(HCkImap cHandle, const char *mailbox, const char *mimeText);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_AppendMimeAsync(HCkImap cHandle, const char *mailbox, const char *mimeText);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AppendMimeWithDate(HCkImap cHandle, const char *mailbox, const char *mimeText, SYSTEMTIME * internalDate);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AppendMimeWithDateStr(HCkImap cHandle, const char *mailbox, const char *mimeText, const char *internalDateStr);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_AppendMimeWithDateStrAsync(HCkImap cHandle, const char *mailbox, const char *mimeText, const char *internalDateStr);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AppendMimeWithFlags(HCkImap cHandle, const char *mailbox, const char *mimeText, BOOL seen, BOOL flagged, BOOL answered, BOOL draft);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_AppendMimeWithFlagsAsync(HCkImap cHandle, const char *mailbox, const char *mimeText, BOOL seen, BOOL flagged, BOOL answered, BOOL draft);
CK_C_VISIBLE_PUBLIC BOOL CkImap_AppendMimeWithFlagsSb(HCkImap cHandle, const char *mailbox, HCkStringBuilder sbMime, BOOL seen, BOOL flagged, BOOL answered, BOOL draft);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_AppendMimeWithFlagsSbAsync(HCkImap cHandle, const char *mailbox, HCkStringBuilder sbMime, BOOL seen, BOOL flagged, BOOL answered, BOOL draft);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Capability(HCkImap cHandle, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_capability(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CapabilityAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_CheckConnection(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkMessageSet CkImap_CheckForNewEmail(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CheckForNewEmailAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC void CkImap_ClearSessionLog(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_CloseMailbox(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CloseMailboxAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Connect(HCkImap cHandle, const char *domainName);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ConnectAsync(HCkImap cHandle, const char *domainName);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Copy(HCkImap cHandle, int msgId, BOOL bUid, const char *copyToMailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CopyAsync(HCkImap cHandle, int msgId, BOOL bUid, const char *copyToMailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_CopyMultiple(HCkImap cHandle, HCkMessageSet messageSet, const char *copyToMailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CopyMultipleAsync(HCkImap cHandle, HCkMessageSet messageSet, const char *copyToMailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_CopySequence(HCkImap cHandle, int startSeqNum, int count, const char *copyToMailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CopySequenceAsync(HCkImap cHandle, int startSeqNum, int count, const char *copyToMailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_CreateMailbox(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_CreateMailboxAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_DeleteMailbox(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_DeleteMailboxAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Disconnect(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_DisconnectAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_ExamineMailbox(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ExamineMailboxAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Expunge(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ExpungeAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_ExpungeAndClose(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ExpungeAndCloseAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchAttachment(HCkImap cHandle, HCkEmail emailObject, int attachmentIndex, const char *saveToPath);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchAttachmentAsync(HCkImap cHandle, HCkEmail emailObject, int attachmentIndex, const char *saveToPath);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchAttachmentBd(HCkImap cHandle, HCkEmail email, int attachmentIndex, HCkBinData binData);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchAttachmentBdAsync(HCkImap cHandle, HCkEmail email, int attachmentIndex, HCkBinData binData);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchAttachmentBytes(HCkImap cHandle, HCkEmail email, int attachIndex, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchAttachmentBytesAsync(HCkImap cHandle, HCkEmail email, int attachIndex);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchAttachmentSb(HCkImap cHandle, HCkEmail email, int attachmentIndex, const char *charset, HCkStringBuilder sb);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchAttachmentSbAsync(HCkImap cHandle, HCkEmail email, int attachmentIndex, const char *charset, HCkStringBuilder sb);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchAttachmentString(HCkImap cHandle, HCkEmail emailObject, int attachmentIndex, const char *charset, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_fetchAttachmentString(HCkImap cHandle, HCkEmail emailObject, int attachmentIndex, const char *charset);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchAttachmentStringAsync(HCkImap cHandle, HCkEmail emailObject, int attachmentIndex, const char *charset);
CK_C_VISIBLE_PUBLIC HCkEmailBundle CkImap_FetchBundle(HCkImap cHandle, HCkMessageSet messageSet);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchBundleAsync(HCkImap cHandle, HCkMessageSet messageSet);
CK_C_VISIBLE_PUBLIC HCkStringArray CkImap_FetchBundleAsMime(HCkImap cHandle, HCkMessageSet messageSet);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchBundleAsMimeAsync(HCkImap cHandle, HCkMessageSet messageSet);
CK_C_VISIBLE_PUBLIC HCkEmailBundle CkImap_FetchChunk(HCkImap cHandle, int startSeqNum, int count, HCkMessageSet failedSet, HCkMessageSet fetchedSet);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchChunkAsync(HCkImap cHandle, int startSeqNum, int count, HCkMessageSet failedSet, HCkMessageSet fetchedSet);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchFlags(HCkImap cHandle, int msgId, BOOL bUid, HCkString outStrFlags);
CK_C_VISIBLE_PUBLIC const char *CkImap_fetchFlags(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchFlagsAsync(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkEmailBundle CkImap_FetchHeaders(HCkImap cHandle, HCkMessageSet messageSet);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchHeadersAsync(HCkImap cHandle, HCkMessageSet messageSet);
CK_C_VISIBLE_PUBLIC HCkEmailBundle CkImap_FetchSequence(HCkImap cHandle, int startSeqNum, int numMessages);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSequenceAsync(HCkImap cHandle, int startSeqNum, int numMessages);
CK_C_VISIBLE_PUBLIC HCkStringArray CkImap_FetchSequenceAsMime(HCkImap cHandle, int startSeqNum, int numMessages);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSequenceAsMimeAsync(HCkImap cHandle, int startSeqNum, int numMessages);
CK_C_VISIBLE_PUBLIC HCkEmailBundle CkImap_FetchSequenceHeaders(HCkImap cHandle, int startSeqNum, int numMessages);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSequenceHeadersAsync(HCkImap cHandle, int startSeqNum, int numMessages);
CK_C_VISIBLE_PUBLIC HCkEmail CkImap_FetchSingle(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSingleAsync(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchSingleAsMime(HCkImap cHandle, int msgId, BOOL bUid, HCkString outStrMime);
CK_C_VISIBLE_PUBLIC const char *CkImap_fetchSingleAsMime(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSingleAsMimeAsync(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchSingleAsMimeSb(HCkImap cHandle, int msgId, BOOL bUid, HCkStringBuilder sbMime);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSingleAsMimeSbAsync(HCkImap cHandle, int msgId, BOOL bUid, HCkStringBuilder sbMime);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchSingleBd(HCkImap cHandle, int msgId, BOOL bUid, HCkBinData mimeData);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSingleBdAsync(HCkImap cHandle, int msgId, BOOL bUid, HCkBinData mimeData);
CK_C_VISIBLE_PUBLIC HCkEmail CkImap_FetchSingleHeader(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSingleHeaderAsync(HCkImap cHandle, int msgId, BOOL bUid);
CK_C_VISIBLE_PUBLIC BOOL CkImap_FetchSingleHeaderAsMime(HCkImap cHandle, int msgId, BOOL bUID, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_fetchSingleHeaderAsMime(HCkImap cHandle, int msgId, BOOL bUID);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_FetchSingleHeaderAsMimeAsync(HCkImap cHandle, int msgId, BOOL bUID);
CK_C_VISIBLE_PUBLIC HCkMessageSet CkImap_GetAllUids(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_GetAllUidsAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_GetMailAttachFilename(HCkImap cHandle, HCkEmail email, int attachIndex, HCkString outStrFilename);
CK_C_VISIBLE_PUBLIC const char *CkImap_getMailAttachFilename(HCkImap cHandle, HCkEmail email, int attachIndex);
CK_C_VISIBLE_PUBLIC int CkImap_GetMailAttachSize(HCkImap cHandle, HCkEmail email, int attachIndex);
CK_C_VISIBLE_PUBLIC BOOL CkImap_GetMailboxStatus(HCkImap cHandle, const char *mailbox, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_getMailboxStatus(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_GetMailboxStatusAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC int CkImap_GetMailFlag(HCkImap cHandle, HCkEmail email, const char *flagName);
CK_C_VISIBLE_PUBLIC int CkImap_GetMailNumAttach(HCkImap cHandle, HCkEmail email);
CK_C_VISIBLE_PUBLIC int CkImap_GetMailSize(HCkImap cHandle, HCkEmail email);
CK_C_VISIBLE_PUBLIC BOOL CkImap_GetQuota(HCkImap cHandle, const char *quotaRoot, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_getQuota(HCkImap cHandle, const char *quotaRoot);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_GetQuotaAsync(HCkImap cHandle, const char *quotaRoot);
CK_C_VISIBLE_PUBLIC BOOL CkImap_GetQuotaRoot(HCkImap cHandle, const char *mailboxName, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_getQuotaRoot(HCkImap cHandle, const char *mailboxName);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_GetQuotaRootAsync(HCkImap cHandle, const char *mailboxName);
CK_C_VISIBLE_PUBLIC HCkCert CkImap_GetSslServerCert(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_HasCapability(HCkImap cHandle, const char *name, const char *capabilityResponse);
CK_C_VISIBLE_PUBLIC BOOL CkImap_IdleCheck(HCkImap cHandle, int timeoutMs, HCkString outStr);
CK_C_VISIBLE_PUBLIC const char *CkImap_idleCheck(HCkImap cHandle, int timeoutMs);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_IdleCheckAsync(HCkImap cHandle, int timeoutMs);
CK_C_VISIBLE_PUBLIC BOOL CkImap_IdleDone(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_IdleDoneAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_IdleStart(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_IdleStartAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_IsConnected(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_IsLoggedIn(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_IsUnlocked(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkMailboxes CkImap_ListMailboxes(HCkImap cHandle, const char *reference, const char *wildcardedMailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ListMailboxesAsync(HCkImap cHandle, const char *reference, const char *wildcardedMailbox);
CK_C_VISIBLE_PUBLIC HCkMailboxes CkImap_ListSubscribed(HCkImap cHandle, const char *reference, const char *wildcardedMailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ListSubscribedAsync(HCkImap cHandle, const char *reference, const char *wildcardedMailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_LoadTaskCaller(HCkImap cHandle, HCkTask task);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Login(HCkImap cHandle, const char *loginName, const char *password);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_LoginAsync(HCkImap cHandle, const char *loginName, const char *password);
CK_C_VISIBLE_PUBLIC BOOL CkImap_LoginSecure(HCkImap cHandle, HCkSecureString loginName, HCkSecureString password);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_LoginSecureAsync(HCkImap cHandle, HCkSecureString loginName, HCkSecureString password);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Logout(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_LogoutAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_MoveMessages(HCkImap cHandle, HCkMessageSet messageSet, const char *destFolder);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_MoveMessagesAsync(HCkImap cHandle, HCkMessageSet messageSet, const char *destFolder);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Noop(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_NoopAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_RefetchMailFlags(HCkImap cHandle, HCkEmail email);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_RefetchMailFlagsAsync(HCkImap cHandle, HCkEmail email);
CK_C_VISIBLE_PUBLIC BOOL CkImap_RenameMailbox(HCkImap cHandle, const char *fromMailbox, const char *toMailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_RenameMailboxAsync(HCkImap cHandle, const char *fromMailbox, const char *toMailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SaveLastError(HCkImap cHandle, const char *path);
CK_C_VISIBLE_PUBLIC HCkMessageSet CkImap_Search(HCkImap cHandle, const char *criteria, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SearchAsync(HCkImap cHandle, const char *criteria, BOOL bUid);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SelectMailbox(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SelectMailboxAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SendRawCommand(HCkImap cHandle, const char *cmd, HCkString outRawResponse);
CK_C_VISIBLE_PUBLIC const char *CkImap_sendRawCommand(HCkImap cHandle, const char *cmd);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SendRawCommandAsync(HCkImap cHandle, const char *cmd);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SendRawCommandB(HCkImap cHandle, const char *cmd, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SendRawCommandBAsync(HCkImap cHandle, const char *cmd);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SendRawCommandC(HCkImap cHandle, HCkByteData cmd, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SendRawCommandCAsync(HCkImap cHandle, HCkByteData cmd);
#if defined(CK_CSP_INCLUDED)
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetCSP(HCkImap cHandle, HCkCsp csp);
#endif
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetDecryptCert(HCkImap cHandle, HCkCert cert);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetDecryptCert2(HCkImap cHandle, HCkCert cert, HCkPrivateKey key);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetFlag(HCkImap cHandle, int msgId, BOOL bUid, const char *flagName, int value);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SetFlagAsync(HCkImap cHandle, int msgId, BOOL bUid, const char *flagName, int value);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetFlags(HCkImap cHandle, HCkMessageSet messageSet, const char *flagName, int value);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SetFlagsAsync(HCkImap cHandle, HCkMessageSet messageSet, const char *flagName, int value);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetMailFlag(HCkImap cHandle, HCkEmail email, const char *flagName, int value);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SetMailFlagAsync(HCkImap cHandle, HCkEmail email, const char *flagName, int value);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetQuota(HCkImap cHandle, const char *quotaRoot, const char *resource, int quota);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SetQuotaAsync(HCkImap cHandle, const char *quotaRoot, const char *resource, int quota);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetSslClientCert(HCkImap cHandle, HCkCert cert);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetSslClientCertPem(HCkImap cHandle, const char *pemDataOrFilename, const char *pemPassword);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SetSslClientCertPfx(HCkImap cHandle, const char *pfxFilename, const char *pfxPassword);
CK_C_VISIBLE_PUBLIC HCkMessageSet CkImap_Sort(HCkImap cHandle, const char *sortCriteria, const char *charset, const char *searchCriteria, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SortAsync(HCkImap cHandle, const char *sortCriteria, const char *charset, const char *searchCriteria, BOOL bUid);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SshAuthenticatePk(HCkImap cHandle, const char *sshLogin, HCkSshKey privateKey);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SshAuthenticatePkAsync(HCkImap cHandle, const char *sshLogin, HCkSshKey privateKey);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SshAuthenticatePw(HCkImap cHandle, const char *sshLogin, const char *sshPassword);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SshAuthenticatePwAsync(HCkImap cHandle, const char *sshLogin, const char *sshPassword);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SshCloseTunnel(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SshCloseTunnelAsync(HCkImap cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkImap_SshOpenTunnel(HCkImap cHandle, const char *sshHostname, int sshPort);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SshOpenTunnelAsync(HCkImap cHandle, const char *sshHostname, int sshPort);
CK_C_VISIBLE_PUBLIC BOOL CkImap_StoreFlags(HCkImap cHandle, int msgId, BOOL bUid, const char *flagNames, int value);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_StoreFlagsAsync(HCkImap cHandle, int msgId, BOOL bUid, const char *flagNames, int value);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Subscribe(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_SubscribeAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkJsonObject CkImap_ThreadCmd(HCkImap cHandle, const char *threadAlg, const char *charset, const char *searchCriteria, BOOL bUid);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_ThreadCmdAsync(HCkImap cHandle, const char *threadAlg, const char *charset, const char *searchCriteria, BOOL bUid);
CK_C_VISIBLE_PUBLIC BOOL CkImap_UnlockComponent(HCkImap cHandle, const char *unlockCode);
CK_C_VISIBLE_PUBLIC BOOL CkImap_Unsubscribe(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC HCkTask CkImap_UnsubscribeAsync(HCkImap cHandle, const char *mailbox);
CK_C_VISIBLE_PUBLIC BOOL CkImap_UseCertVault(HCkImap cHandle, HCkXmlCertVault vault);
CK_C_VISIBLE_PUBLIC BOOL CkImap_UseSsh(HCkImap cHandle, HCkSsh ssh);
CK_C_VISIBLE_PUBLIC BOOL CkImap_UseSshTunnel(HCkImap cHandle, HCkSocket tunnel);
#endif
