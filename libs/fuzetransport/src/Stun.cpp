//
//  Stun.cpp
//  FuzeTransport
//
//  Created by Tim Na on 9/18/15.
//  Copyright © 2015 FuzeBox. All rights reserved.
//
#include <Stun.h>
#include <TransportImpl.h>
#include <openssl/hmac.h> // HMAC-SHA1 - ice credential
#include <zlib.h>         // crc32 - ice credential

#include <Log.h>

namespace fuze {
namespace stun {
    
const uint16_t MSG_HEADER   = 20;
const uint16_t MSG_TYPE     = 2;
const uint16_t MSG_LENGTH   = 2;
const uint16_t MSG_COOKIE   = 4;
const uint16_t MSG_TRANS_ID = 12;
const uint16_t ATTR_HEADER  = 4;
const uint16_t ATTR_ID      = 2;
const uint16_t ATTR_LENGTH  = 2;
const uint32_t CRC_XOR_VAL  = 0x5354554e;
const uint32_t MAGIC_COOKIE = 0x2112a442;

const uint16_t ATTR_MSG_INT = 24;
const uint16_t ATTR_FINGERP = 8;

bool IsStun(const char* pMsg, uint32_t size)
{
    bool result = false;
    
    if (pMsg && ((*pMsg & 0xc0) == 0) && (size > 8)) {
        uint32_t magic = htonl(MAGIC_COOKIE);
        if (memcmp(pMsg+MSG_TYPE+MSG_LENGTH, &magic, MSG_COOKIE) == 0) {
            result = true;
        }
    }
    
    return result;
}

Type GetType(const char* pMsg, uint32_t size)
{
    char cbits = 0;
    
    if ((*pMsg & 0x01) == 1) cbits |= 0x02;
    if ((*(pMsg+1) & 0x10) == 1) cbits |= 0x01;
    
    switch (cbits)
    {
        case 0:  return REQUEST;
        case 1:  return INDICATION;
        case 2:  return SUCCESS;
        case 3:  return FAILURE;
        default: return INVALID;
    }
}

Method GetMethod(const char* pMsg, uint32_t size)
{
    Method method = UNKNOWN;
    
    uint16_t header = 0;
    memcpy(&header, pMsg, MSG_TYPE);
    header = ntohs(header);
    switch (header & 0xFEEF)
    {
        case BINDING: method = BINDING; break;
        default:;
    }
    
    return method;
}

bool GetTransactionID(const char* pMsg, uint32_t size, uint8_t* pTransID)
{
    bool result = false;
    
    const char* p = pMsg + MSG_TYPE + MSG_LENGTH + MSG_COOKIE;
    
    if (p < pMsg + size) {
        memcpy(pTransID, p, MSG_TRANS_ID);
        result = true;
    }
    
    return result;
}

void PrintAttribute(uint16_t attrId, const char* pAttr, uint32_t len)
{
    bool is_val_str = (len ? true : false);
    for (const char* p = pAttr; (uint32_t)(p - pAttr) < len; ++p) {
        if (32 <= *p && *p <= 126) {
            is_val_str = false;
            break;
        }
    }
    
    switch (attrId)
    {
        case XOR_MAPPED_ADDRESS:
            // if this is IPv4 then print it
            if (len == 8 && pAttr[1] == 0x01) {
                uint16_t xor_port;
                memcpy(&xor_port , pAttr+2, sizeof(uint16_t));
                xor_port = ntohs(xor_port) ^ uint16_t(MAGIC_COOKIE>>16);
                uint32_t xor_ip;
                memcpy(&xor_ip, pAttr+4, sizeof(uint32_t));
                xor_ip = ntohl(xor_ip) ^ MAGIC_COOKIE;
                sockaddr_in addr;
                addr.sin_addr.s_addr = htonl(xor_ip);
                char ip_buf[INET_ADDRSTRLEN] = { "0.0.0.0" };
                if (evutil_inet_ntop(AF_INET, &addr.sin_addr,
                                     ip_buf, INET_ADDRSTRLEN)) {
                    _MLOG_(toStr((Attribute)attrId) << " (" <<
                           len << "B): " << ip_buf << ":" << xor_port);
                    break;
                }
            }
        case MESSAGE_INTEGRITY:
        case FINGERPRINT:
        case USERNAME:
        case PRIORITY:
        case USE_CANDIDATE:
        case ICE_CONTROLLED:
        case ICE_CONTROLLING:
            _MLOG_(toStr((Attribute)attrId) << " (" << len <<
                   "B): " << (is_val_str ? pAttr : "") << " [" <<
                   (is_val_str ? Hex(0, 0) : Hex((uint8_t*)pAttr, len)) << "]");
            break;
        default:
            _WLOG_("Unknown ID: " << Hex((uint8_t*)&attrId, MSG_TYPE) <<
                   " (" << len << "B): " << (is_val_str ? pAttr : "") << " [" <<
                   Hex((uint8_t*)pAttr, len) << "]");
    }
}

void PrintStun(const char* pMsg, uint32_t size)
{
    if (!IsStun(pMsg, size)) {
        return;
    }
    
    const char* p = pMsg + MSG_TYPE; // set to length
    
    // get message length which is unpadded length of attributes
    uint16_t msg_len = 0;
    memcpy(&msg_len, p, MSG_LENGTH);
    msg_len = ntohs(msg_len);
    
    p += MSG_LENGTH + MSG_COOKIE + MSG_TRANS_ID;
    
    // start parsing attribute
    while (p < pMsg+size) {
        
        // attribute id
        uint16_t attr_id = 0;
        memcpy(&attr_id, p, ATTR_ID);
        attr_id = ntohs(attr_id);
        
        // attribute length
        uint16_t attr_len = 0;
        memcpy(&attr_len, p+ATTR_ID, ATTR_LENGTH);
        attr_len = ntohs(attr_len);
        
        // check if attr_length makes sense here
        if (p + ATTR_HEADER + attr_len > pMsg+size) {
            _ELOG_("attribute length overflow: " << attr_len << "B");
            return;
        }
        
        PrintAttribute(attr_id, p+ATTR_HEADER, attr_len);
        
        p += (ATTR_HEADER + attr_len);
        uint16_t padding = attr_len % 4;
        if (padding > 0) p += (4-padding);
    }
}

bool Validate(const char* pMsg, uint32_t size, const string& rPwd, bool bNoLog)
{
    bool bVerified[2] = { false, false };
    
    if (!IsStun(pMsg, size)) {
        return false;
    }
    
    const char* p = pMsg + MSG_TYPE; // set to length
    
    // get message length which is unpadded length of attributes
    uint16_t msg_len = 0;
    memcpy(&msg_len, p, MSG_LENGTH);
    msg_len = ntohs(msg_len);
    
    p += MSG_LENGTH + MSG_COOKIE + MSG_TRANS_ID;
    
    // start parsing attribute
    while (p < pMsg+size) {
        
        // attribute id
        uint16_t attr_id = 0;
        memcpy(&attr_id, p, ATTR_ID);
        attr_id = ntohs(attr_id);
        
        // attribute length
        uint16_t attr_len = 0;
        memcpy(&attr_len, p+ATTR_ID, ATTR_LENGTH);
        attr_len = ntohs(attr_len);
        
        // check if attr_length makes sense here
        if (p + ATTR_HEADER + attr_len > pMsg+size) {
            _ELOG_("attribute length overflow: " << attr_len << "B");
            return false;
        }
        
        const char* p_val = p + ATTR_HEADER;
        
        if (attr_id == MESSAGE_INTEGRITY) {
            // for message integrity, validate the value
            // calculate the length including message integrity attribute length
            int msg_int_len = p - pMsg;
            int hmac_len = msg_int_len - MSG_HEADER + (ATTR_HEADER + attr_len);
            hmac_len = htons(hmac_len);
            memcpy((void*)(pMsg+MSG_TYPE), &hmac_len, MSG_LENGTH);
            
            // now run HMAC on this
            uint8_t  md[EVP_MAX_MD_SIZE];
            uint32_t md_len = 0;
            
            /* Calculate HMAC of buffer using the secret */
            HMAC(EVP_sha1(), rPwd.c_str(), rPwd.size(),
                 (uint8_t*)pMsg, msg_int_len, md, &md_len);
            
            if (md_len == attr_len) {
                if (memcmp(md, p_val, attr_len) == 0) {
                    if (!bNoLog) _MLOG_("Message integrity verified using " << rPwd);
                    bVerified[0] = true;
                }
                else {
                    _ELOG_("Message integrity not matching (expected " <<
                           Hex(md, md_len) << ") using " << rPwd);
                }
            }
            else {
                _ELOG_("Unexpected Message Integirty length: " << attr_len);
            }
            
            // put the length back
            uint16_t len_back = htons(msg_len);
            memcpy((void*)(pMsg+MSG_TYPE), &len_back, MSG_LENGTH);
        }
        else if (attr_id == FINGERPRINT) {
            int crc_len = p - pMsg;
            uint32_t crc_value = crc32(0, (uint8_t*)pMsg, crc_len);
            crc_value ^= CRC_XOR_VAL;
            crc_value = htonl(crc_value);
            if (memcmp(p_val, &crc_value, attr_len) == 0) {
                if (!bNoLog) _MLOG_("Fingerprint CRC32 verified");
                bVerified[1] = true;
            }
            else {
                _ELOG_("Fingerprint CRC32 failed (expected " <<
                       Hex((uint8_t*)p_val, attr_len) << " vs " <<
                       Hex((uint8_t*)&crc_value, attr_len) << ")");
            }
        }
        else if (!bNoLog) {
            PrintAttribute(attr_id, p_val, attr_len);
        }
        
        // advance to next attribute
        p += (ATTR_HEADER + attr_len);
        
        // skip the padding if exist
        uint16_t padding = attr_len % 4;
        if (padding > 0) {
            _DLOG_("skipping padding bytes of " << 4-padding);
            p += (4-padding);
        }
    }
    
    return (bVerified[0] && bVerified[1]);
}

void WriteMessageIntegrityAndFingerPrint(Buffer::Ptr spStun, const string& rPwd)
{
    uint8_t* p_buf = spStun->getBuf();
    
    // first get current position which include head and attributes so far
    uint16_t pos = (uint16_t)spStun->position();
    
    // length for att_len so far including 'not yet included' message integrity
    // write the current attribute length prior to calculating message integrity
    uint16_t attr_len = htons(pos - MSG_HEADER + ATTR_MSG_INT);
    memcpy(p_buf+MSG_TYPE, &attr_len, MSG_TYPE);
    
    // write MESSAGE INTEGRITY attribute
    uint8_t  md[EVP_MAX_MD_SIZE];
    uint32_t md_len = 0;
    HMAC(EVP_sha1(), rPwd.c_str(), rPwd.size(), p_buf, pos, md, &md_len);
    spStun->write2(uint16_t(MESSAGE_INTEGRITY));
    spStun->write2(uint16_t(md_len));
    spStun->write(md, md_len);
    
    // write FINGERPRINT attribute
    pos = (uint16_t)spStun->position();
    attr_len = htons(pos - MSG_HEADER + ATTR_FINGERP);
    memcpy(p_buf+MSG_TYPE, &attr_len, MSG_TYPE);
    uint32_t crc_value = crc32(0, p_buf, pos);
    crc_value ^= CRC_XOR_VAL;
    spStun->write2(uint16_t(FINGERPRINT));
    spStun->write2(uint16_t(4));
    spStun->write2(crc_value);
}

NetworkBuffer::Ptr CreateBindResponse(const uint8_t* pTransID,
                                      const Address& rAddress,
                                      const string&  rPwd)
{
    NetworkBuffer::Ptr sp_resp(new NetworkBuffer(512));
    sp_resp->setDebugInfo(__FILE__, __LINE__);
    
    // write stun header
    sp_resp->write2(uint16_t(0x0101));
    sp_resp->write2(uint16_t(0)); // this will be filled with FINGERPRINT
    sp_resp->write2(MAGIC_COOKIE);
    sp_resp->write(pTransID, MSG_TRANS_ID);
    
    // write XOR_MAPPED_ADDRESS attribute
    sp_resp->write2(uint16_t(XOR_MAPPED_ADDRESS));
    sp_resp->write2(uint16_t(8));
    sp_resp->write(uint8_t(0)); // reserved
    sp_resp->write(uint8_t(0x01)); // IPv4
    uint16_t xor_port = rAddress.Port() ^ uint16_t(MAGIC_COOKIE>>16);
    sp_resp->write2(xor_port);
    uint32_t xor_ip = ntohl(rAddress.IPNum().s_addr) ^ MAGIC_COOKIE;
    sp_resp->write2(xor_ip);
    
    if (!rPwd.empty()) {
        WriteMessageIntegrityAndFingerPrint(sp_resp, rPwd);
    }

    // set the buf size as position length as it is true length
    sp_resp->setSize(sp_resp->position());
    
    return sp_resp;
}

NetworkBuffer::Ptr CreateBindRequest(const string&  username,
                                     const uint8_t* transID,
                                     const string&  rPwd,
                                     bool           bNoIce)
{
    NetworkBuffer::Ptr sp_req(new NetworkBuffer(512));
    sp_req->setDebugInfo(__FILE__, __LINE__);
    
    // write stun header
    sp_req->write2(uint16_t(BINDING));
    sp_req->write2(uint16_t(0)); // filled later with FINGERPRINT
    sp_req->write2(MAGIC_COOKIE);
    sp_req->write(transID, MSG_TRANS_ID);
    
    // write USERNAME attribute
    uint16_t user_len = (uint16_t)username.size();
    sp_req->write2(uint16_t(USERNAME));
    sp_req->write2(user_len);
    sp_req->write((uint8_t*)username.c_str(), user_len);
    if (int padding = (user_len%4)) {
        padding = 4 - padding;
        uint8_t empty = 0;
        for (int i = 0; i < padding; ++i) {
            sp_req->write(empty);
        }
    }
    
    if (!bNoIce) {
        bool server_role = TransportImpl::GetInstance()->IsAppServer();
        Attribute attr_role = (server_role ? ICE_CONTROLLED : ICE_CONTROLLING);
        
        // write ICE-CONTROLLED
        uint64_t tm = (uint64_t)GetTimeMs();
        sp_req->write2(uint16_t(attr_role));
        sp_req->write2(uint16_t(8));
        sp_req->write2(uint32_t(tm>>32));
        sp_req->write2(uint32_t(tm));
        
        // write PRIORITY
        uint32_t priority = uint32_t(2^24)*126 + (2^8)*65535 + 255; // RTP
        sp_req->write2(uint16_t(PRIORITY));
        sp_req->write2(uint16_t(4));
        sp_req->write2(priority);
    }
    
    if (!rPwd.empty()) {
        WriteMessageIntegrityAndFingerPrint(sp_req, rPwd);
    }

    // set the buf size as position length as it is true length
    sp_req->setSize(sp_req->position());
    
    return sp_req;
}
    
} // namespace stun

const char* toStr(stun::Type eType)
{
    switch (eType)
    {
        case stun::REQUEST:    return "Stun Request";
        case stun::INDICATION: return "Stun Indication";
        case stun::SUCCESS:    return "Stun Success Response";
        case stun::FAILURE:    return "Stun Failure Response";
        default:               return "INVALID";
    }
}

const char* toStr(stun::Method type)
{
    switch (type)
    {
        case stun::BINDING: return "BINDING";
        default:            return "UNKNOWN";
    }
}

const char* toStr(stun::Attribute eAttr)
{
    switch (eAttr)
    {
        case stun::USERNAME:           return "USERNAME";
        case stun::MESSAGE_INTEGRITY:  return "MESSAGE-INTEGRITY";
        case stun::XOR_MAPPED_ADDRESS: return "XOR-MAPPED-ADDRESS";
        case stun::PRIORITY:           return "PRIORITY";
        case stun::USE_CANDIDATE:      return "USE-CANDIDATE";
        case stun::FINGERPRINT:        return "FINGERPRINT";
        case stun::ICE_CONTROLLED:     return "ICE-CONTROLLED";
        case stun::ICE_CONTROLLING:    return "ICE-CONTROLLING";
        default:                       return "UNKNOWN";
    }
}
    
} // namespace fuze
