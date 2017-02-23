//
//  Common.h
//  FuzeTransport
//
//  Created by Tim Na on 2/14/17.
//  Copyright © 2017 Fuze. All rights reserved.
//

#ifndef Common_h
#define Common_h

#include <string>
#include <vector>
#include <map>
#include <list>

#ifdef FREE_SWITCH
#include "Buffer.h"
#else
#include <fuze/core/Buffer.h> // includes fuzememory.h
#endif

using std::string;
using std::vector;
using std::list;
using std::map;

#endif /* Common_h */
