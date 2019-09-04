//
//  Compat.h
//
//  Created by Tim Na on 11/13/13.
//  Copyright (c) 2013 FuzeBox. All rights reserved.
//

#ifndef COMPAT_H_
#define COMPAT_H_

#ifdef WIN32

#define RESTRICT __restrict

#define STACKVAR(type, varname, count) type* varname=reinterpret_cast<type*>(_alloca(sizeof(type) * (count)))

#else // not WIN32

#define STACKVAR(type, varname, count) type varname[count]

#endif

#endif
