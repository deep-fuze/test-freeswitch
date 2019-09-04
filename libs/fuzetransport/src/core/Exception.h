//
//  Exception.h
//  FuzeTransport
//
//  Created by Raghavendra Thodime on 12/20/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef __FUZE_EXCEPTION_H__
#define __FUZE_EXCEPTION_H__

#include <string>
using std::string;

namespace fuze {

class TransportException : public std::exception
{
public:
    TransportException(const char * str) : str_(str) {}

    inline virtual ~TransportException() throw()
    {
    }

    virtual const char* what() const throw() { return str_.c_str(); }
    
private:
    string str_;
};
 
class InitException : public TransportException
{
public:
    InitException(const char *str) : TransportException(str) {}

    inline virtual ~InitException() throw()
    {
    }
};
    
} //namespace fuze

#endif