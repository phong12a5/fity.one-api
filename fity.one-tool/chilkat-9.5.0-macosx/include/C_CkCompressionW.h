// This is a generated source file for Chilkat version 9.5.0.88
#ifndef _C_CkCompressionWH
#define _C_CkCompressionWH
#include "chilkatDefs.h"

#include "Chilkat_C.h"


CK_C_VISIBLE_PUBLIC void CkCompressionW_setAbortCheck(HCkCompressionW cHandle, BOOL (*fnAbortCheck)(void));
CK_C_VISIBLE_PUBLIC void CkCompressionW_setPercentDone(HCkCompressionW cHandle, BOOL (*fnPercentDone)(int pctDone));
CK_C_VISIBLE_PUBLIC void CkCompressionW_setProgressInfo(HCkCompressionW cHandle, void (*fnProgressInfo)(const wchar_t *name, const wchar_t *value));
CK_C_VISIBLE_PUBLIC void CkCompressionW_setTaskCompleted(HCkCompressionW cHandle, void (*fnTaskCompleted)(HCkTaskW hTask));

CK_C_VISIBLE_PUBLIC HCkCompressionW CkCompressionW_Create(void);
CK_C_VISIBLE_PUBLIC void CkCompressionW_Dispose(HCkCompressionW handle);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getAlgorithm(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putAlgorithm(HCkCompressionW cHandle, const wchar_t *newVal);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_algorithm(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getCharset(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putCharset(HCkCompressionW cHandle, const wchar_t *newVal);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_charset(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getDebugLogFilePath(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putDebugLogFilePath(HCkCompressionW cHandle, const wchar_t *newVal);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_debugLogFilePath(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC int CkCompressionW_getDeflateLevel(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putDeflateLevel(HCkCompressionW cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getEncodingMode(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putEncodingMode(HCkCompressionW cHandle, const wchar_t *newVal);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_encodingMode(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC int CkCompressionW_getHeartbeatMs(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putHeartbeatMs(HCkCompressionW cHandle, int newVal);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getLastErrorHtml(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_lastErrorHtml(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getLastErrorText(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_lastErrorText(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getLastErrorXml(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_lastErrorXml(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_getLastMethodSuccess(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putLastMethodSuccess(HCkCompressionW cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_getVerboseLogging(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC void  CkCompressionW_putVerboseLogging(HCkCompressionW cHandle, BOOL newVal);
CK_C_VISIBLE_PUBLIC void CkCompressionW_getVersion(HCkCompressionW cHandle, HCkString retval);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_version(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginCompressBytes(HCkCompressionW cHandle, HCkByteData data, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginCompressBytesAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginCompressBytes2(HCkCompressionW cHandle, const void * pByteData, unsigned long szByteData, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginCompressBytesENC(HCkCompressionW cHandle, HCkByteData data, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_beginCompressBytesENC(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginCompressBytesENCAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginCompressString(HCkCompressionW cHandle, const wchar_t *str, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginCompressStringAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginCompressStringENC(HCkCompressionW cHandle, const wchar_t *str, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_beginCompressStringENC(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginCompressStringENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginDecompressBytes(HCkCompressionW cHandle, HCkByteData data, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginDecompressBytesAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginDecompressBytes2(HCkCompressionW cHandle, const void * pByteData, unsigned long szByteData, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginDecompressBytesENC(HCkCompressionW cHandle, const wchar_t *str, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginDecompressBytesENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginDecompressString(HCkCompressionW cHandle, HCkByteData data, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_beginDecompressString(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginDecompressStringAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_BeginDecompressStringENC(HCkCompressionW cHandle, const wchar_t *str, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_beginDecompressStringENC(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_BeginDecompressStringENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressBd(HCkCompressionW cHandle, HCkBinDataW binData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressBdAsync(HCkCompressionW cHandle, HCkBinDataW binData);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressBytes(HCkCompressionW cHandle, HCkByteData data, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressBytesAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressBytes2(HCkCompressionW cHandle, const void * pByteData, unsigned long szByteData, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressBytesENC(HCkCompressionW cHandle, HCkByteData data, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_compressBytesENC(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressBytesENCAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressFile(HCkCompressionW cHandle, const wchar_t *srcPath, const wchar_t *destPath);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressFileAsync(HCkCompressionW cHandle, const wchar_t *srcPath, const wchar_t *destPath);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressSb(HCkCompressionW cHandle, HCkStringBuilderW sb, HCkBinDataW binData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressSbAsync(HCkCompressionW cHandle, HCkStringBuilderW sb, HCkBinDataW binData);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressStream(HCkCompressionW cHandle, HCkStreamW strm);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressStreamAsync(HCkCompressionW cHandle, HCkStreamW strm);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressString(HCkCompressionW cHandle, const wchar_t *str, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressStringAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_CompressStringENC(HCkCompressionW cHandle, const wchar_t *str, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_compressStringENC(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_CompressStringENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressBd(HCkCompressionW cHandle, HCkBinDataW binData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressBdAsync(HCkCompressionW cHandle, HCkBinDataW binData);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressBytes(HCkCompressionW cHandle, HCkByteData data, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressBytesAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressBytes2(HCkCompressionW cHandle, const void * pByteData, unsigned long szByteData, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressBytesENC(HCkCompressionW cHandle, const wchar_t *encodedCompressedData, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressBytesENCAsync(HCkCompressionW cHandle, const wchar_t *encodedCompressedData);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressFile(HCkCompressionW cHandle, const wchar_t *srcPath, const wchar_t *destPath);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressFileAsync(HCkCompressionW cHandle, const wchar_t *srcPath, const wchar_t *destPath);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressSb(HCkCompressionW cHandle, HCkBinDataW binData, HCkStringBuilderW sb);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressSbAsync(HCkCompressionW cHandle, HCkBinDataW binData, HCkStringBuilderW sb);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressStream(HCkCompressionW cHandle, HCkStreamW strm);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressStreamAsync(HCkCompressionW cHandle, HCkStreamW strm);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressString(HCkCompressionW cHandle, HCkByteData data, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_decompressString(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressStringAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_DecompressStringENC(HCkCompressionW cHandle, const wchar_t *encodedCompressedData, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_decompressStringENC(HCkCompressionW cHandle, const wchar_t *encodedCompressedData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_DecompressStringENCAsync(HCkCompressionW cHandle, const wchar_t *encodedCompressedData);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndCompressBytes(HCkCompressionW cHandle, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndCompressBytesAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndCompressBytesENC(HCkCompressionW cHandle, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_endCompressBytesENC(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndCompressBytesENCAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndCompressString(HCkCompressionW cHandle, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndCompressStringAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndCompressStringENC(HCkCompressionW cHandle, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_endCompressStringENC(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndCompressStringENCAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndDecompressBytes(HCkCompressionW cHandle, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndDecompressBytesAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndDecompressBytesENC(HCkCompressionW cHandle, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndDecompressBytesENCAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndDecompressString(HCkCompressionW cHandle, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_endDecompressString(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndDecompressStringAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_EndDecompressStringENC(HCkCompressionW cHandle, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_endDecompressStringENC(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_EndDecompressStringENCAsync(HCkCompressionW cHandle);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_LoadTaskCaller(HCkCompressionW cHandle, HCkTaskW task);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreCompressBytes(HCkCompressionW cHandle, HCkByteData data, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreCompressBytesAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreCompressBytes2(HCkCompressionW cHandle, const void * pByteData, unsigned long szByteData, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreCompressBytesENC(HCkCompressionW cHandle, HCkByteData data, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_moreCompressBytesENC(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreCompressBytesENCAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreCompressString(HCkCompressionW cHandle, const wchar_t *str, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreCompressStringAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreCompressStringENC(HCkCompressionW cHandle, const wchar_t *str, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_moreCompressStringENC(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreCompressStringENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreDecompressBytes(HCkCompressionW cHandle, HCkByteData data, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreDecompressBytesAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreDecompressBytes2(HCkCompressionW cHandle, const void * pByteData, unsigned long szByteData, HCkByteData outBytes);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreDecompressBytesENC(HCkCompressionW cHandle, const wchar_t *str, HCkByteData outData);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreDecompressBytesENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreDecompressString(HCkCompressionW cHandle, HCkByteData data, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_moreDecompressString(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreDecompressStringAsync(HCkCompressionW cHandle, HCkByteData data);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_MoreDecompressStringENC(HCkCompressionW cHandle, const wchar_t *str, HCkString outStr);
CK_C_VISIBLE_PUBLIC const wchar_t *CkCompressionW_moreDecompressStringENC(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC HCkTaskW CkCompressionW_MoreDecompressStringENCAsync(HCkCompressionW cHandle, const wchar_t *str);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_SaveLastError(HCkCompressionW cHandle, const wchar_t *path);
CK_C_VISIBLE_PUBLIC BOOL CkCompressionW_UnlockComponent(HCkCompressionW cHandle, const wchar_t *unlockCode);
#endif
