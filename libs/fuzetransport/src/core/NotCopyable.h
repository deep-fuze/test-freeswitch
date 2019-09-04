//
//  NotCopyable.h
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//
#ifndef NOTCOPYABLE_H_
#define NOTCOPYABLE_H_

namespace fuze
{

class NotCopyable
{
protected:
    inline NotCopyable()
    {
    }

    inline virtual ~NotCopyable()
    {
    }

private:
    NotCopyable(const NotCopyable&);
    NotCopyable& operator=(const NotCopyable&);
};

} // namespace fuze

#endif // NOTCOPYABLE_H_

