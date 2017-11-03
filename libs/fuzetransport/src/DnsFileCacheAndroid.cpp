//
//  DnsFileCacheAndroid.cpp
//  FuzeTransport
//
//  Created by Tim Na on 9/27/17.
//  Copyright © 2017 Fuze. All rights reserved.
//
#include <string>

#include <jni.h>
#include "CJNIContext.h"
#include <Log.h>

#define _LOG_(A,B) DEBUG_OUT(A, AREA_COM, __FUZE_FUNC__ << ": " << B)

namespace fuze {

using std::string;

class DnsFileCache
{
public:
    static DnsFileCache* GetInstance() {
        static DnsFileCache dns;
        return &dns;
    }
            
    bool GetString(string name, string& rOutput)
    {
        jni::CJNIContextEnv::Ptr env = jniContext_.attachJvm();

        if (env->_get()->ExceptionCheck() == JNI_TRUE) {
            ELOG("Exception check failed");
            return false;
        }
        
        jmethodID getStringMethodId;
        if (env->methodIdWithName("getString", "(Ljava/lang/String;[Ljava/lang/String;)Z", getStringMethodId) == false) {
            return false;
        }

        jstring emptyStr = env->newString("");
        jclass stringClass = (*env)->FindClass("java/lang/String");
        jobjectArray objectArray = (jobjectArray) (*env)->NewObjectArray(1, stringClass, emptyStr);
        (*env)->DeleteLocalRef(stringClass);
        
        jstring key = env->newString(name);
        jboolean wasFound = (*env)->CallStaticBooleanMethod(env->getClass(), getStringMethodId, key, objectArray);
        
        if (wasFound) {
            
            jstring jretValue = (jstring)(*env)->GetObjectArrayElement(objectArray, 0);
            const char *valueChars = (*env)->GetStringUTFChars(jretValue, 0);
            rOutput = valueChars;
            (*env)->ReleaseStringUTFChars(jretValue, valueChars);
            (*env)->DeleteLocalRef(jretValue);
        }

        (*env)->DeleteLocalRef(objectArray);
        (*env)->DeleteLocalRef(key);
        (*env)->DeleteLocalRef(emptyStr);

        return wasFound;
    }
    

    void SetString(string name, string& rValue)
    {
        jni::CJNIContextEnv::Ptr env = jniContext_.attachJvm();

        if (env->_get()->ExceptionCheck() == JNI_TRUE) {
            ELOG("Exception check failed");
            return;
        }

        env->callStaticVoidMethod("setString", "(Ljava/lang/String;Ljava/lang/String;)V", name, rValue);
    }

private:
    DnsFileCache()
        : jniContext_("SharedPreferencesHelper") // hihacking applayer's preference helper
    {
    }
    
    jni::CJNIContext  jniContext_;
};


void SetDnsFileCache(string cache)
{
    DnsFileCache::GetInstance()->SetString("DnsCache", cache);
}

void GetDnsFileCache(string& rCache)
{
    DnsFileCache::GetInstance()->GetString("DnsCache", rCache);
}

} // namespace fuze
