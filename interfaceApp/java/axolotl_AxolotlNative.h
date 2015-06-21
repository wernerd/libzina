/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class axolotl_AxolotlNative */

#ifndef _Included_axolotl_AxolotlNative
#define _Included_axolotl_AxolotlNative
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     axolotl_AxolotlNative
 * Method:    doInit
 * Signature: (ILjava/lang/String;[B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_doInit
  (JNIEnv *, jobject, jint, jstring, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    sendMessage
 * Signature: ([B[B[B)[J
 */
JNIEXPORT jlongArray JNICALL Java_axolotl_AxolotlNative_sendMessage
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getKnownUsers
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_getKnownUsers
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getOwnIdentityKey
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_getOwnIdentityKey
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getIdentityKeys
 * Signature: ([B)[[B
 */
JNIEXPORT jobjectArray JNICALL Java_axolotl_AxolotlNative_getIdentityKeys
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getAxoDevicesUser
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_getAxoDevicesUser
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    registerAxolotlDevice
 * Signature: ([I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_registerAxolotlDevice
  (JNIEnv *, jclass, jintArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    newPreKeys
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_newPreKeys
  (JNIEnv *, jclass, jint);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getNumPreKeys
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_getNumPreKeys
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getErrorCode
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_getErrorCode
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    getErrorInfo
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_axolotl_AxolotlNative_getErrorInfo
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    testCommand
 * Signature: (Ljava/lang/String;[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_testCommand
  (JNIEnv *, jclass, jstring, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    axoCommand
 * Signature: (Ljava/lang/String;[B)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_axolotl_AxolotlNative_axoCommand
  (JNIEnv *, jclass, jstring, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    repoOpenDatabase
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_repoOpenDatabase
  (JNIEnv *, jclass, jstring);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    repoCloseDatabase
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_axolotl_AxolotlNative_repoCloseDatabase
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    repoIsOpen
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_axolotl_AxolotlNative_repoIsOpen
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    existConversation
 * Signature: ([B)Z
 */
JNIEXPORT jboolean JNICALL Java_axolotl_AxolotlNative_existConversation
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    storeConversation
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_storeConversation
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadConversation
 * Signature: ([B[I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_loadConversation
  (JNIEnv *, jclass, jbyteArray, jintArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    deleteConversation
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_deleteConversation
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    listConversations
 * Signature: ()[[B
 */
JNIEXPORT jobjectArray JNICALL Java_axolotl_AxolotlNative_listConversations
  (JNIEnv *, jclass);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    insertEvent
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_insertEvent
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadEvent
 * Signature: ([B[B[I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_loadEvent
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jintArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    existEvent
 * Signature: ([B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_axolotl_AxolotlNative_existEvent
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadEvents
 * Signature: ([BII[I)[[B
 */
JNIEXPORT jobjectArray JNICALL Java_axolotl_AxolotlNative_loadEvents
  (JNIEnv *, jclass, jbyteArray, jint, jint, jintArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    deleteEvent
 * Signature: ([B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_deleteEvent
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    insertObject
 * Signature: ([B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_insertObject
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadObject
 * Signature: ([B[B[B[I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_axolotl_AxolotlNative_loadObject
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jintArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    existObject
 * Signature: ([B[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_axolotl_AxolotlNative_existObject
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    loadObjects
 * Signature: ([B[B[I)[[B
 */
JNIEXPORT jobjectArray JNICALL Java_axolotl_AxolotlNative_loadObjects
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jintArray);

/*
 * Class:     axolotl_AxolotlNative
 * Method:    deleteObject
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL Java_axolotl_AxolotlNative_deleteObject
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
