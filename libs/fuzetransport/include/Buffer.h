#ifndef _TRANSPORT_BUFFER_H_
#define _TRANSPORT_BUFFER_H_

#include <ciso646>

#if (__cplusplus >= 201103L) || defined(_MSC_VER) // Use libc++
#include <memory>
#else
#include <tr1/memory>
#endif

#if (__cplusplus >= 201103L) || defined(_MSC_VER) // Use libc++
    #define fuze_shared_ptr std::shared_ptr
    #define fuze_weak_ptr std::weak_ptr
    #define fuze_dynamic_pointer_cast std::dynamic_pointer_cast
#else
    #define fuze_shared_ptr std::tr1::shared_ptr
    #define fuze_weak_ptr std::tr1::weak_ptr
    #define fuze_dynamic_pointer_cast std::tr1::dynamic_pointer_cast
#endif

#include <stdint.h>
#include <stdexcept>
#include <arpa/inet.h>
#include <string.h>

namespace fuze {
namespace core {

struct RawMemory
{
    typedef fuze_shared_ptr<RawMemory> Ptr;

    uint8_t* pBuf_;
    uint32_t size_;
    uint32_t realSize_;
    int      appId_;

    RawMemory(uint32_t size, uint32_t realSize)
        : pBuf_(new uint8_t[realSize]), size_(size), realSize_(realSize), appId_(-1) {}
    ~RawMemory() { if (pBuf_) delete[] pBuf_; }

    uint8_t* getBuf() { return pBuf_; }
    uint32_t size()   { return size_; }
    uint32_t getRealSize() { return realSize_; }
    void     setSize(uint32_t size) { size_ = size; }
    void     setDebugInfo(const char* pFile, int line) {}
    int      getAppID() { return appId_; }
    void     setAppID(int appId) { appId_ = appId; }
};

#define MAKE make

class Buffer
{
public:
    typedef fuze_shared_ptr<Buffer> Ptr;

    static Ptr make(uint32_t size) {
        return Ptr(new Buffer(size));
    }
    
    static Ptr makeShallowCopy(const Ptr& rFrom) {
        Ptr sp_copy(new Buffer(*rFrom));
        return sp_copy;
    }

    void setDebugInfo(const char* pFile, int line) {}

    void init(RawMemory::Ptr spMem) {
        size_     = spMem->size();
        spRawBuf_ = spMem;
    }
    
    void reset() {
        position_ = 0;
        offset_   = 0;
        size_     = 0;
        spRawBuf_.reset();
    }
    
    void setAsShallowCopy(Buffer::Ptr& spBuf) {
        if (spBuf) {
            offset_   = spBuf->offset_;
            size_     = spBuf->size_;
            position_ = spBuf->position_;
            spRawBuf_ = spBuf->spRawBuf_;
        }
    }
    
    uint32_t getOffset() const      { return offset_; }  
    uint8_t* getBuf()               { return spRawBuf_->pBuf_ + offset_; }
    const uint8_t* getBuf() const   { return spRawBuf_->pBuf_ + offset_; }
    RawMemory::Ptr getRawBuf()      { return spRawBuf_; }

    uint32_t size() const           { return size_;   } 
    void     setSize(uint32_t size) { size_ = size;   }

    void push(uint32_t bytes) {
        if (offset_ >= bytes) {
            offset_ -= bytes;
            size_   += bytes;
        }
    }

    void pull(uint32_t bytes) {
        if (bytes <= size_) {
            offset_ += bytes;
            size_   -= bytes;
        }
    }

    uint32_t position() { return position_; }

    void write(const uint8_t _val) {
        uint8_t* addr = _adjustPosition(sizeof(_val));
        addr[0] = _val & 0xff;
    }
        
    void write2(const uint16_t _val) {
        uint8_t* addr = _adjustPosition(sizeof(_val));
        uint16_t val = htons(_val);
        memcpy(addr, &val, sizeof(uint16_t));
    }
        
    void write2(const uint32_t _val) {      
        uint8_t* addr = _adjustPosition(sizeof(_val));
        uint32_t val = htonl(_val);
        memcpy(addr, &val, sizeof(uint32_t));
    }
        
    void write2(const uint64_t _val) {
        uint8_t* addr = _adjustPosition(sizeof(_val));
        uint64_t val  = _val;
        uint16_t tmp  = 1;
        uint8_t* p    = (uint8_t*)&tmp;
        if (*p == 1) {
            p = (uint8_t*)&val;
            uint8_t t = p[0];
            p[0] = p[7]; p[7] = t;
            t = p[1]; p[1] = p[6]; p[6] = t;
            t = p[2]; p[2] = p[5]; p[5] = t;
            t = p[3]; p[3] = p[4]; p[4] = t;
        }
        memcpy(addr, &val, sizeof(uint64_t));
    }
        
    void write(const uint8_t* _val, uint32_t _size) {
        uint8_t* addr = _adjustPosition(_size);
        memcpy(addr, _val, _size);
    }
        
    uint8_t* _adjustPosition(uint32_t _typeSize) {
        if ((position_ + _typeSize) > size_) {
            throw std::runtime_error("Reading beyond end of buffer!");
        }
        
        position_ += _typeSize;
        
        return (uint8_t*)(spRawBuf_->pBuf_ + offset_ + position_ - _typeSize);
    }

    virtual ~Buffer() {}

protected:

    Buffer(const Buffer& rRhs) {
        offset_   = rRhs.offset_;
        size_     = rRhs.size_;
        position_ = rRhs.position_;
        spRawBuf_ = rRhs.spRawBuf_;
    }

    Buffer(uint32_t size) {
        offset_   = 0;
        size_     = size;
        position_ = 0;
        spRawBuf_.reset(new RawMemory(size, size));
    }
    
    Buffer() {
        offset_   = 0;
        size_     = 0;
        position_ = 0;
    }

    uint32_t        offset_;
    uint32_t        size_;
    uint32_t        position_;
    RawMemory::Ptr  spRawBuf_;
};

} // namespace core
} // namespace fuze


#endif // _TRANSPORT_BUFFER_H_
